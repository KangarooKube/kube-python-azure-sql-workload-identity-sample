import struct
import os
from sqlalchemy import text, event
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime as dt
from azure.identity import DefaultAzureCredential
import pyodbc
from logging.config import dictConfig

# setup logging
dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default",
            }
        },
        "root": {"level": "DEBUG", "handlers": ["console"]},
    }
)

# disable connection pooling to ensure no conflict with token expiry
pyodbc.pooling = False

# define connection string variables
server_name = os.environ.get("SERVERNAME", "drocx-eus1")
database_name = os.environ.get("DATABASENAME", "free-db")
driver = "{ODBC Driver 18 for SQL Server}"
connection_string = (f"Driver={driver};Server=tcp:{server_name}.database.windows.net,1433;Database={database_name};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30")

# globally set SQL Server ODBC driver for access token
SQL_COPT_SS_ACCESS_TOKEN = 1256  

# initialize flask app using SQLAlchemy for SQL Server ODBC calls
db = SQLAlchemy()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mssql+pyodbc:///?odbc_connect=%s" % connection_string
db.init_app(app)

# function to display token expiry
def azure_jwt_expiry(token): 
  decoded_token = jwt.decode(token, options={"verify_signature": False})
  token_expiry = dt.fromtimestamp(int(decoded_token['exp'])) 
  return token_expiry 

# function to generate Azure SQL specific access token and log token expiry
def get_azure_sql_odbc_token():
  credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
  token = credential.get_token("https://database.windows.net/.default").token
  token_bytes = token.encode("UTF-16-LE")
  token_expiry = azure_jwt_expiry(token)
  token_struct = struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)
  return token_struct, token_expiry

# a listener to hijack all database connections and inject access token
with app.app_context():
  @event.listens_for(db.engine, "do_connect")
  def provide_token(dialect, conn_rec, cargs, cparams):
    # remove the "Trusted_Connection" parameter that SQLAlchemy adds
    # cargs[0] = cargs[0].replace(";Trusted_Connection=Yes", "")
    token = get_azure_sql_odbc_token()
    token_struct = token[0]
    app.logger.info(f"Token Expiry: {token[1]}")
    cparams["attrs_before"] = {SQL_COPT_SS_ACCESS_TOKEN: token_struct}

# simple default site to bring back Azure SQL version as a page
@app.route('/', methods=['GET'])
def home():
  query = text("SELECT @@version")
  rows = db.session.execute(query).fetchall()
  for row in rows:
    app.logger.info(f"Query Results: {row}")
  return f"<p>{rows}</p>"

app.run(host='0.0.0.0', port=8080)
