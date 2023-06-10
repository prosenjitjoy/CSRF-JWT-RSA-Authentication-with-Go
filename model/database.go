package model

import (
	"log"

	"github.com/gocql/gocql"
)

// CREATE KEYSPACE csrfjwt WITH replication = {'class':'NetworkTopologyStrategy', 'datacenter1': 3};

const createTable = `
CREATE TABLE IF NOT EXISTS users (
	first_name text,
	last_name text,
	user_name text,
	email text,
	password text,
	phone text,
	auth_token text,
	refresh_token text,
	user_type text,
	user_id text,
	created_at timestamp,
	updated_at timestamp,
	PRIMARY KEY((last_name), user_name, email)
)`

const createTableByEmail = `
CREATE MATERIALIZED VIEW IF NOT EXISTS getUserByEmail
AS SELECT * FROM users
WHERE email IS NOT NULL
AND last_name IS NOT NULL
AND user_name IS NOT NULL
PRIMARY KEY(email, last_name, user_name)
`

func DBSession() *gocql.Session {
	cluster := gocql.NewCluster("127.0.0.1", "127.0.0.2", "127.0.0.3")
	cluster.Keyspace = "csrfjwt"

	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatal("unable to connect to cassandra cluster:", err)
	}

	err = session.Query(createTable).Exec()
	if err != nil {
		log.Fatal("unable to create users table:", err)
	}

	err = session.Query(createTableByEmail).Exec()
	if err != nil {
		log.Fatal("unable to create email table:", err)
	}

	return session
}
