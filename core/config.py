from dotenv import load_dotenv
import os
load_dotenv()


SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "sraGbRmjYQXmYdnrgPk!OFE35UP6n/QqeoED=iu/bUXBFSSPwnsuprP6T45Qsbwywu2khUka!6IIleY",
)

if not SECRET_KEY:
    SECRET_KEY = os.urandom(32)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 30
REFRESH_TOKEN_EXPIRES_MINUTES = 15 * 24 * 60  # 15 days

MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = os.getenv("MYSQL_PORT", "3306")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "An123")
MYSQL_DB = os.getenv("MYSQL_DB", "music")