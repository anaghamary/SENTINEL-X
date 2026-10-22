import os


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinel_x.db")
JWT_SECRET = os.getenv("JWT_SECRET", "local-development-secret-change-before-deployment")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60
NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")
EVIDENCE_ENCRYPTION_KEY = os.getenv("EVIDENCE_ENCRYPTION_KEY")
