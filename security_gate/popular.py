"""Popular package names: typosquatters pick names one or two letters away from these.

A short curated list keeps the check offline and fast (SlopGuard's layer 1 is network-free).
Extend freely; comparisons are case-insensitive.
"""

PYPI = frozenset("""
requests urllib3 boto3 botocore numpy pandas django flask fastapi pydantic sqlalchemy
pytest setuptools pip wheel six python-dateutil pyyaml certifi idna charset-normalizer
cryptography pyjwt jinja2 werkzeug click rich typer httpx aiohttp celery redis psycopg2
psycopg2-binary pymysql matplotlib scipy scikit-learn tensorflow torch transformers
openai anthropic langchain beautifulsoup4 lxml pillow selenium paramiko gunicorn uvicorn
stripe twilio sendgrid flask-cors flask-login flask-sqlalchemy marshmallow alembic
python-dotenv tqdm colorama pytz attrs packaging protobuf grpcio google-auth
""".split())

NPM = frozenset("""
react react-dom next vue angular express lodash axios moment dayjs chalk commander
debug dotenv uuid jsonwebtoken bcrypt mongoose sequelize pg mysql2 redis cors helmet
body-parser cookie-parser multer socket.io ws webpack vite typescript eslint prettier
jest mocha chai nodemon ts-node zod yup joi passport nodemailer stripe openai
tailwindcss postcss autoprefixer babel-core @babel/core rxjs graphql apollo-server
""".split())


def popular_for(ecosystem: str) -> frozenset[str]:
    return PYPI if ecosystem == "PyPI" else NPM
