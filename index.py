from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

# List all databases
print("Databases:", client.list_database_names())
