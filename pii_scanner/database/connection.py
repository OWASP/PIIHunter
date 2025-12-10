"""
Database connection management with pooling and context managers.

Provides safe, read-only access to PostgreSQL with proper resource cleanup.
"""

import psycopg2
from psycopg2 import pool, extras
from contextlib import contextmanager
from typing import Optional, Generator
import structlog

logger = structlog.get_logger(__name__)


class DatabaseConnection:
    """
    Manages PostgreSQL connections with pooling.

    Uses connection pooling to efficiently manage database connections
    and provides context managers for safe resource handling.
    """

    def __init__(
        self,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
        sslmode: str = "require",
        min_conn: int = 1,
        max_conn: int = 10,
    ):
        """
        Initialize database connection pool.

        Args:
            host: Database host
            port: Database port
            database: Database name
            user: Database user (should be read-only role)
            password: Database password
            sslmode: SSL mode (require, verify-ca, verify-full)
            min_conn: Minimum connections in pool
            max_conn: Maximum connections in pool
        """
        self.config = {
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "password": password,
            "sslmode": sslmode,
        }

        try:
            self.pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=min_conn,
                maxconn=max_conn,
                **self.config
            )
            logger.info(
                "database_pool_created",
                host=host,
                database=database,
                user=user,
                min_conn=min_conn,
                max_conn=max_conn,
            )
        except psycopg2.Error as e:
            logger.error("database_connection_failed", error=str(e))
            raise

    @contextmanager
    def get_connection(self) -> Generator:
        """
        Get a connection from the pool.

        Yields:
            A psycopg2 connection object

        Example:
            with db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
        """
        conn = None
        try:
            conn = self.pool.getconn()
            # Ensure read-only mode for safety
            conn.set_session(readonly=True, autocommit=False)
            yield conn
        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            logger.error("database_error", error=str(e))
            raise
        finally:
            if conn:
                self.pool.putconn(conn)

    @contextmanager
    def get_cursor(self, cursor_factory=None) -> Generator:
        """
        Get a cursor from a pooled connection.

        Args:
            cursor_factory: Optional cursor factory (e.g., RealDictCursor)

        Yields:
            A psycopg2 cursor object

        Example:
            with db.get_cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM users LIMIT 10")
                rows = cur.fetchall()
        """
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cursor
            finally:
                cursor.close()

    @contextmanager
    def get_dict_cursor(self) -> Generator:
        """
        Get a cursor that returns rows as dictionaries.

        Yields:
            A RealDictCursor object

        Example:
            with db.get_dict_cursor() as cur:
                cur.execute("SELECT id, email FROM users LIMIT 1")
                row = cur.fetchone()
                print(row['email'])
        """
        with self.get_cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            yield cursor

    @contextmanager
    def get_server_cursor(self, name: str = "scanner_cursor") -> Generator:
        """
        Get a server-side cursor for streaming large result sets.

        Server-side cursors don't load all results into memory at once,
        making them ideal for scanning large tables.

        Args:
            name: Cursor name (must be unique per connection)

        Yields:
            A server-side cursor

        Example:
            with db.get_server_cursor() as cur:
                cur.execute("SELECT * FROM large_table")
                while True:
                    rows = cur.fetchmany(1000)
                    if not rows:
                        break
                    process_batch(rows)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor(name=name)
            try:
                yield cursor
            finally:
                cursor.close()

    def execute_write(self, sql: str, params: Optional[tuple] = None):
        """
        Execute a write operation (INSERT, UPDATE, DELETE).

        This is for writing to the security_pii schema only.
        The connection is temporarily set to read-write mode.

        Args:
            sql: SQL statement to execute
            params: Optional parameters for the query

        Raises:
            psycopg2.Error: If the query fails
        """
        conn = None
        try:
            conn = self.pool.getconn()
            # Allow writes for metadata schema
            conn.set_session(readonly=False, autocommit=False)

            with conn.cursor() as cur:
                cur.execute(sql, params)
                conn.commit()
                logger.debug("write_operation_executed", sql=sql[:100])

        except psycopg2.Error as e:
            if conn:
                conn.rollback()
            logger.error("write_operation_failed", error=str(e), sql=sql[:100])
            raise
        finally:
            if conn:
                self.pool.putconn(conn)

    def execute_query(
        self,
        sql: str,
        params: Optional[tuple] = None,
        fetch_one: bool = False,
    ):
        """
        Execute a SELECT query and return results.

        Args:
            sql: SQL query to execute
            params: Optional parameters for the query
            fetch_one: If True, return only the first row

        Returns:
            Query results (list of tuples, or single tuple if fetch_one=True)
        """
        with self.get_cursor() as cur:
            cur.execute(sql, params)
            if fetch_one:
                return cur.fetchone()
            return cur.fetchall()

    def test_connection(self) -> bool:
        """
        Test the database connection.

        Returns:
            True if connection is successful, False otherwise
        """
        try:
            with self.get_cursor() as cur:
                cur.execute("SELECT 1")
                result = cur.fetchone()
                return result[0] == 1
        except Exception as e:
            logger.error("connection_test_failed", error=str(e))
            return False

    def close(self):
        """Close all connections in the pool."""
        if self.pool:
            self.pool.closeall()
            logger.info("database_pool_closed")
