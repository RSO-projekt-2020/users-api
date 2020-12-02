#!/bin/bash

name="user-db"

# Only run db if user-db container isnt already running
[[ $(docker ps -f "name=$name" --format '{{.Names}}') == $name ]] || sudo docker run -d --name $name -e POSTGRES_USER=dbuser -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=$name -p 5432:5432 postgres:13
cat sql-scripts/init.sql | sudo docker exec -i $name psql -U dbuser -d $name
