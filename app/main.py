# pylint: disable=no-member
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from flask import abort, Flask, request, Response
from flask_cors import CORS
from jose import jwt
import json
from os import getenv
import re
from uuid import uuid4

app = Flask(__name__)

# CONFIG
if (app.config['ENV'] == 'development'):
    app.config.from_object('settings')
else:
    app.config['APP_ACCOUNT_ID'] = getenv('APP_ACCOUNT_ID')
    app.config['APP_AUDIENCE'] = getenv('APP_AUDIENCE')
    app.config['APP_IDENTITY_POOL_ID'] = getenv('APP_IDENTITY_POOL_ID')
    app.config['APP_IDENTITY_PROVIDER_NAME'] = getenv('APP_IDENTITY_PROVIDER_NAME')
    app.config['APP_ISSUER'] = getenv('APP_ISSUER')
    app.config['APP_JWKS'] = getenv('APP_JWKS')
    app.config['APP_REGION'] = getenv('APP_REGION')
jwks = json.loads(app.config['APP_JWKS'])

CORS(app)
todosTable = None

def initialize_ddb(access_key_id, secret_key, session_token):
    global todosTable
    if (app.config['ENV'] == 'development'):
        ddb = boto3.resource(
            'dynamodb',
            endpoint_url='http://localhost:8000',
        )
        todosTable = ddb.Table('Todos')
    else:
        ddb = boto3.resource(
            'dynamodb', 
            region_name=app.config['APP_REGION'],
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )
        todosTable = ddb.Table('Todos')

def authenticate():
    authorization = request.headers.get('authorization')
    if (authorization == None):
        abort(401)
    m = re.search('^Bearer (.*)', authorization)
    if (m == None):
        abort(401)
    token = m.group(1)
    try:
        payload = jwt.decode(token, jwks, audience=app.config['APP_AUDIENCE'], options={
            'verify_at_hash': False,
        })
    except:
        abort(401)
    if (payload['iss'] != app.config['APP_ISSUER']):
        abort(401)
    if (payload['token_use'] != 'id'):
        abort(401)
    client = boto3.client('cognito-identity', 'us-east-1')
    try:
        response = client.get_id(
            AccountId=app.config['APP_ACCOUNT_ID'],
            IdentityPoolId=app.config['APP_IDENTITY_POOL_ID'],
            Logins=dict([(app.config['APP_IDENTITY_PROVIDER_NAME'], token)])
        )
        identity_id = response['IdentityId']
        response = client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins=dict([(app.config['APP_IDENTITY_PROVIDER_NAME'], token)])
        )
        access_key_id = response['Credentials']['AccessKeyId']
        secret_key = response['Credentials']['SecretKey']
        session_token= response['Credentials']['SessionToken']
        initialize_ddb(access_key_id, secret_key, session_token)
        return identity_id
    except:
        abort(401)

@app.route('/hc')
def hc():
    return 'healthy'

@app.route('/todos')
def read():
    identity_id = authenticate()
    try:
        response = todosTable.query(
            ExpressionAttributeNames={"#N":"Name"},
            KeyConditionExpression=Key('IdentityId').eq(identity_id),
            ProjectionExpression='Id, #N',
            Select='SPECIFIC_ATTRIBUTES'
        )
        todos = response['Items']
        todos_json = json.dumps(todos)
        return Response(todos_json, mimetype='application/json')
    except:
        abort(500)

@app.route('/todos', methods=['POST'])
def create():
    identity_id = authenticate()
    request_dict = request.json
    if request_dict == None:
        abort(400)
    if not 'Name' in request_dict:
        abort(400)
    name = request_dict['Name']
    if not isinstance(name, str):
        abort(400)
    try:
        id = str(uuid4())
        item = {
            'IdentityId': identity_id,
            'Id': id,
            'Name': name,
        }
        todosTable.put_item(Item=item)
        return {
            'Id': id,
            'Name': name,
        }
    except:
        abort(500)


@app.route('/todos/<id>', methods=['DELETE'])
def delete(id):
    identity_id = authenticate()
    key = {
        'IdentityId': identity_id,
        'Id': id,
    }
    try:
        todosTable.delete_item(
            ConditionExpression=Attr('IdentityId').eq(identity_id) & Attr('Id').eq(id),
            Key=key
        )
        return {
            'Id': id,
        }
    except ClientError as e:  
        if e.response['Error']['Code']=='ConditionalCheckFailedException':  
            abort(404)
        else:
            abort(500)
    except:
        abort(500)