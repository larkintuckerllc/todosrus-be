# pylint: disable=no-member
import boto3
from botocore.exceptions import ClientError
from flask import abort, Flask, request, Response
from flask_cors import CORS
import json
from os import getenv
from uuid import uuid4

region = getenv('REGION')

# SUPPORT LOCAL DEVELOPMENT
localhost = getenv('LOCALHOST')
if (localhost == None):
    ddb = boto3.resource('dynamodb', region_name=region)
else:
    ddb = boto3.resource('dynamodb', endpoint_url='http://localhost:8000')

Attr = boto3.dynamodb.conditions.Attr
todosTable = ddb.Table('Todos')
app = Flask(__name__)
CORS(app)

@app.route('/todos')
def read():
    try:
        response = todosTable.scan()
        todos = response['Items']
        todos_json = json.dumps(todos)
        return Response(todos_json, mimetype='application/json')
    except:
        abort(500)

@app.route('/todos', methods=['POST'])
def create():
    request_dict = request.json
    if request_dict == None:
        abort(400)
        return
    if not 'Name' in request_dict:
        abort(400)
        return
    name = request_dict['Name']
    if not isinstance(name, str):
        abort(400)
        return
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