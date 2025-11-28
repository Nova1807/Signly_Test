// Seed file to insert a sample user into the MongoDB database
// Run with: docker-compose exec mongodb mongosh mongodb://admin:password@localhost:27017/admin --file /tmp/seed.js

db.auth('admin', 'password');
db = db.getSiblingDB('signly');

db.users.insertOne({
    name: "Erik Hauer",
    email: "erik.hauer@outlook.de",
    password: "erik1807" // Note: This should be hashed in production
});

print("User seeded successfully");
