aws dynamodb create-table \
    --table-name Todos \
    --attribute-definitions \
    AttributeName=IdentityId,AttributeType=S \
    AttributeName=Id,AttributeType=S \
    --key-schema \
    AttributeName=IdentityId,KeyType=HASH \
    AttributeName=Id,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
    --endpoint-url http://localhost:8000

aws dynamodb create-table \
    --table-name Subscriptions \
    --attribute-definitions \
    AttributeName=IdentityId,AttributeType=S \
    --key-schema \
    AttributeName=IdentityId,KeyType=HASH \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
    --endpoint-url http://localhost:8000
