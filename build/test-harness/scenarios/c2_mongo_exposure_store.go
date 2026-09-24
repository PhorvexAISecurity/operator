package scenarios

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Each method is one exact MongoDB operation; the client disables the driver's
// transparent read/write retries. Ambiguous results are never replayed.
type mongoExposureStore interface {
	ServerVersion(context.Context) (string, error)
	SourceConfiguration(context.Context) error
	CollectionUUID(context.Context, string, string) (string, error)
	CreateCollection(context.Context, string, string) error
	Insert(context.Context, string, string, mongoExposureDocument) (any, error)
	Read(context.Context, string, string, string) (mongoExposureDocument, error)
	Count(context.Context, string, string) (int64, error)
	Drop(context.Context, string, string, string) error
	Close(context.Context) error
}

type mongoExposureDriver struct{ client *mongo.Client }

func (d *mongoExposureDriver) ServerVersion(ctx context.Context) (string, error) {
	var result struct {
		Version string  `bson:"version"`
		OK      float64 `bson:"ok"`
	}
	if err := d.client.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&result); err != nil {
		return "", err
	}
	if result.OK != 1 || result.Version == "" {
		return "", errors.New("Mongo buildInfo version unavailable")
	}
	return result.Version, nil
}

// Read only the two reviewed process-shape fields. The command can contain
// other values, so neither the raw response nor unexpected fields are logged.
func (d *mongoExposureDriver) SourceConfiguration(ctx context.Context) error {
	var row bson.M
	if err := d.client.Database("admin").RunCommand(ctx, bson.D{{Key: "getCmdLineOpts", Value: 1}}).Decode(&row); err != nil {
		return errors.New("Mongo getCmdLineOpts unavailable")
	}
	return mongoExposureSourceConfiguration(row)
}

func mongoExposureSourceConfiguration(row bson.M) error {
	if ok, isNumber := row["ok"].(float64); !isNumber || ok != 1 {
		return errors.New("Mongo process configuration ACK differs")
	}
	parsed, ok := mongoExposureBSONObject(row["parsed"])
	if !ok {
		return errors.New("Mongo parsed process configuration unavailable")
	}
	network, ok := mongoExposureBSONObject(parsed["net"])
	if !ok || network["bindIp"] != "*" {
		return errors.New("Mongo process network bind differs")
	}
	if securityRaw, found := parsed["security"]; found {
		security, ok := mongoExposureBSONObject(securityRaw)
		if !ok {
			return errors.New("Mongo security configuration malformed")
		}
		if _, declared := security["authorization"]; declared {
			return errors.New("Mongo authorization configuration changed; no uncredentialed seed")
		}
	}
	return nil
}

func mongoExposureBSONObject(raw any) (bson.M, bool) {
	switch v := raw.(type) {
	case bson.M:
		return v, true
	case bson.D:
		out := bson.M{}
		for _, field := range v {
			if _, duplicate := out[field.Key]; duplicate {
				return nil, false
			}
			out[field.Key] = field.Value
		}
		return out, true
	default:
		return nil, false
	}
}

func newMongoExposureDriver(ctx context.Context, port int) (mongoExposureStore, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("Mongo forwarded port invalid")
	}
	uri := fmt.Sprintf("mongodb://127.0.0.1:%d/?directConnection=true&serverSelectionTimeoutMS=3000&socketTimeoutMS=3000&retryReads=false&retryWrites=false", port)
	opts := options.Client().ApplyURI(uri).SetRetryReads(false).SetRetryWrites(false).SetMaxPoolSize(1).SetServerSelectionTimeout(3 * time.Second).SetTimeout(5 * time.Second)
	client, err := mongo.Connect(opts)
	if err != nil {
		return nil, err
	}
	if err = client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.WithoutCancel(ctx))
		return nil, err
	}
	return &mongoExposureDriver{client: client}, nil
}

func (d *mongoExposureDriver) Close(ctx context.Context) error { return d.client.Disconnect(ctx) }

func (d *mongoExposureDriver) CollectionUUID(ctx context.Context, dbName, collName string) (string, error) {
	cur, err := d.client.Database(dbName).ListCollections(ctx, bson.M{"name": collName})
	if err != nil {
		return "", err
	}
	defer cur.Close(ctx)
	if !cur.Next(ctx) {
		if err := cur.Err(); err != nil {
			return "", err
		}
		return "", nil
	}
	var row struct {
		Name string `bson:"name"`
		Type string `bson:"type"`
		Info struct {
			UUID bson.Binary `bson:"uuid"`
		} `bson:"info"`
	}
	if err = cur.Decode(&row); err != nil {
		return "", err
	}
	if row.Name != collName || row.Type != "collection" || row.Info.UUID.Subtype != 4 || len(row.Info.UUID.Data) != 16 {
		return "", errors.New("Mongo collection UUID or type differs")
	}
	if cur.Next(ctx) || cur.Err() != nil {
		return "", errors.New("Mongo collection listing has extra or incomplete result")
	}
	return hex.EncodeToString(row.Info.UUID.Data), nil
}

func (d *mongoExposureDriver) CreateCollection(ctx context.Context, dbName, collName string) error {
	return d.client.Database(dbName).CreateCollection(ctx, collName)
}

func (d *mongoExposureDriver) Insert(ctx context.Context, dbName, collName string, doc mongoExposureDocument) (any, error) {
	result, err := d.client.Database(dbName).Collection(collName).InsertOne(ctx, doc)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("Mongo insert ACK absent")
	}
	return result.InsertedID, nil
}

func (d *mongoExposureDriver) Read(ctx context.Context, dbName, collName, id string) (mongoExposureDocument, error) {
	var doc mongoExposureDocument
	err := d.client.Database(dbName).Collection(collName).FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
	return doc, err
}

func (d *mongoExposureDriver) Count(ctx context.Context, dbName, collName string) (int64, error) {
	return d.client.Database(dbName).Collection(collName).CountDocuments(ctx, bson.D{})
}

func mongoExposureDropCommand(collName, uuid string) (bson.D, error) {
	data, err := hex.DecodeString(uuid)
	if err != nil || len(data) != 16 || len(collName) < 7 {
		return nil, errors.New("Mongo exact UUID drop authority invalid")
	}
	return bson.D{{Key: "drop", Value: collName}, {Key: "collectionUUID", Value: bson.Binary{Subtype: 4, Data: data}}}, nil
}

func (d *mongoExposureDriver) Drop(ctx context.Context, dbName, collName, uuid string) error {
	command, err := mongoExposureDropCommand(collName, uuid)
	if err != nil {
		return err
	}
	// MongoDB 7.0.40 checks collectionUUID under its exclusive collection
	// lock. An unsupported server or mismatch is terminal; never retry by name.
	var result struct {
		OK float64 `bson:"ok"`
	}
	if err = d.client.Database(dbName).RunCommand(ctx, command).Decode(&result); err != nil {
		return err
	}
	if result.OK != 1 {
		return errors.New("Mongo exact UUID drop ACK unavailable")
	}
	return nil
}
