# pylint: disable=no-member
import boto3
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
    app.config['APP_AUDIENCE'] = getenv('APP_AUDIENCE')
    app.config['APP_ISSUER'] = getenv('APP_ISSUER')
    app.config['APP_JWKS'] = getenv('APP_JWKS')
    app.config['APP_REGION'] = getenv('APP_REGION')
jwks = json.loads(app.config['APP_JWKS'])

CORS(app)
if (app.config['ENV'] == 'development'):
    ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8000')
else:
    ddb = boto3.resource('dynamodb', region_name=app.config['APP_REGION'])
Attr = boto3.dynamodb.conditions.Attr
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
    """
    client = boto3.client('cognito-identity', 'us-east-1')
    try:
        response = client.get_id(
            AccountId='143287522423',
            IdentityPoolId='us-east-1:3f2d50a3-8bd4-4457-b5c5-406f27603d3d',
            Logins={
                'cognito-idp.us-east-1.amazonaws.com/us-east-1_rIytU4eSc': token,
            }
        )
    except:
        abort(401)
        return
    """
    return token

@app.route('/hc')
def hc():
    return 'healthy'

@app.route('/todos')
def read():
    authenticate()
    try:
        response = todosTable.scan()
        todos = response['Items']
        todos_json = json.dumps(todos)
        return Response(todos_json, mimetype='application/json')
    except:
        abort(500)

@app.route('/todos', methods=['POST'])
def create():
    authenticate()
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
            'Id': id,
            'Name': name
        }
        todosTable.put_item(Item=item)
        return item
    except:
        abort(500)


@app.route('/todos/<id>', methods=['DELETE'])
def delete(id):
    authenticate()
    key = {
        'Id': id
    }
    try:
        todosTable.delete_item(
            ConditionExpression=Attr('Id').eq(id),
            Key=key
        )
        return key
    except ClientError as e:  
        if e.response['Error']['Code']=='ConditionalCheckFailedException':  
            abort(404)
        else:
            abort(500)
    except:
        abort(500)