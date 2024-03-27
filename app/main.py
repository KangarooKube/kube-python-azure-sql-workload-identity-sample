import struct
import os
from sqlalchemy import text, event
from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime
from azure.identity import DefaultAzureCredential, WorkloadIdentityCredential
import pyodbc
import json
from logging.config import dictConfig
from tzlocal import get_localzone_name

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
server_name = os.environ.get("SERVERNAME")
database_name = os.environ.get("DATABASENAME")
driver = "{ODBC Driver 18 for SQL Server}"
connection_string = (f"Driver={driver};Server=tcp:{server_name}.database.windows.net,1433;Database={database_name};Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30")

# globally set SQL Server ODBC driver for access token
SQL_COPT_SS_ACCESS_TOKEN = 1256  

# initialize flask app using SQLAlchemy for SQL Server ODBC calls
db = SQLAlchemy()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "mssql+pyodbc:///?odbc_connect=%s" % connection_string
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
  "pool_recycle": 1799, # recommended: kill the pool before Azure SQL gateway kills the connection at 30 mins of inactivity
  "pool_pre_ping": True, # recommended: test connection before use to catch token expiry or other transient errors
  "echo_pool": True, # recommended: log pool actions to know when pooled connections drop
  "echo": False, # optional: log database statements and calls
  "pool_timeout": 30 # optional: limit time waiting for connection from pool
}
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
db.init_app(app)

# function to display token expiry
def get_azure_jwt_expiry(token): 
  decoded_token = jwt.decode(token, options={"verify_signature": False})
  token_expiry = datetime.fromtimestamp(int(decoded_token['exp'])) 
  return token_expiry 

def get_azure_federated_token():
  token = open(os.environ.get("AZURE_FEDERATED_TOKEN_FILE"), "r")
  decoded_token = jwt.decode(token.read(), options={"verify_signature": False})
  return decoded_token

def get_azure_sql_token():
    try:
    # speed up token generation is Workload Identity is enabled to skip testing other methods
      if os.environ.get("AZURE_FEDERATED_TOKEN_FILE"):
        credential = WorkloadIdentityCredential()
        app.logger.info(f"Using Workload Identity for token Azure token generation.")
      else:
        # use DefaultAzureCredential for local development and testing
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
        app.logger.info(f"Using Default Azure Credential for token diagnostics.")
      token = credential.get_token("https://database.windows.net/.default").token
      return token
    except Exception as e:
      app.logger.error(e)
      app.logger.error(f"Azure SQL token generation failed!")
      return

# function to generate Azure SQL specific access token and output along with token expiry
def get_azure_sql_odbc_token():
  try:
    # speed up token generation is Workload Identity is enabled to skip testing other methods
    token = get_azure_sql_token()
    token_bytes = token.encode("UTF-16-LE")
    token_expiry = get_azure_jwt_expiry(token)
    token_struct = struct.pack(f'<I{len(token_bytes)}s', len(token_bytes), token_bytes)
    return token_struct, token_expiry
  except Exception as e:
    app.logger.error(e)
    app.logger.error(f"ODBC token struct generation failed!")
    return

# a listener to hijack all database connections and inject access token
with app.app_context():
  @event.listens_for(db.engine, "do_connect")
  def provide_token(dialect, conn_rec, cargs, cparams):
    token = get_azure_sql_odbc_token()
    if not token:
      raise Exception("Token returned as empty value!")
    else:
      token_struct = token[0]
      app.logger.info(f"Token expiry: {token[1]}")
      cparams["attrs_before"] = {SQL_COPT_SS_ACCESS_TOKEN: token_struct}

# simple default site to bring back Azure SQL version as a page
@app.route('/', methods=['GET'])
def home():
  query = text("SELECT @@SERVERNAME as serverName, DB_NAME() as databaseName, @@VERSION as serverVersion")
  current_datatime = datetime.now()
  time_zone = get_localzone_name()
  try: 
    results = db.session.execute(query).first()
  except Exception as e:
    app.logger.error(e)
    return f"<p>Query failed review logs!</p>", 500
  finally:
    db.session.remove()
  app.logger.info(f"Query results: {results}")
  server_name = results[0]
  database_name = results[1]
  server_version = results[2]
  return render_template('index.html', serverName=server_name, databaseName=database_name, serverVersion=server_version, currentDatatime=current_datatime, timeZone=time_zone)

# endpoint to see Azure SQL token that is being generated
@app.route('/diagnostics/azuresqltoken', methods=['GET'])
def diagnostics_azure_sql_token():
  try: 
    token = get_azure_sql_token()
    decoded_token = jwt.decode(token, options={"verify_signature": False})
    return jsonify(decoded_token)
  except Exception as e:
    app.logger.error(e)
    return f"<p>Query failed get Azure SQL token!</p>", 500

# endpoint to see Azure Workload Identity Federation token being passed to OIDC endpoint
@app.route('/diagnostics/azurefederationtoken', methods=['GET'])
def diagnostics_azure_federation_token():
  try: 
    decoded_token = get_azure_federated_token()
    return jsonify(decoded_token)
  except Exception as e:
    app.logger.error(e)
    return f"<p>Query failed get Azure Workload Identity Federation token!</p>", 500

app.run(host='0.0.0.0', port=8080)
