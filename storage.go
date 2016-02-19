package main

import (
	"errors"
	"github.com/boltdb/bolt"
	"os"
	"time"
)

type Storage struct {
	db *bolt.DB
}

func NewStorage(dbpath string, mode os.FileMode) (Storage, error) {
	db, err := bolt.Open(dbpath, mode, &bolt.Options{Timeout: 5 * time.Second})

	return Storage{
		db: db,
	}, err
}

func (s *Storage) Write(bucket, key, value string) error {
	var err error
	var b *bolt.Bucket
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err = tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		err = b.Put([]byte(key), []byte(value))

		return err
	})
}

func (s *Storage) Read(bucket, key string) (string, error) {
	var err error
	var value string
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return errors.New("Bucket not found")
		}

		buf := b.Get([]byte(key))

		value = string(buf)

		return nil
	})

	return value, err
}

func (s *Storage) Close() {
	s.db.Close()
}
