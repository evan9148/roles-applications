var express = require("express");
var bodyParser = require("body-parser");
var jwt = require("jsonwebtoken");
var app = express();
let cookieParser = require('cookie-parser');
app.use(cookieParser())
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const { url } = require("inspector");
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
var port = 4000;



// Function to write logs (used by Super Admin)
function writeLog(log) {
    fs.appendFileSync(path.join(__dirname, "logs.txt"), log + "\n");
}


// Middleware to verify JWT token and extract user data from it
function verifyToken(req, res, next) {
    const tokenFromHeader = req.headers.authorization;

    if (!tokenFromHeader) {
        res.sendStatus(403);
    } else {
        jwt.verify(tokenFromHeader, "secret_key", (err, authData) => {
            if (err) {
                res.sendStatus(403);
            } else {
                req.authData = authData;
                next();
            }
        });
    }
}

// function verifyToken(req, res, next) {
//     const token = req.cookies.token || req.headers.authorization?.split(" ")[1] || "";

//     jwt.verify(token, "secret_key", (err, decoded) => {
//         if (err) {
//             res.sendStatus(403);
//         } else {
//             req.authData = decoded;
//             next();
//         }
//     });
// }




const knex = require("knex")({
    client: "mysql",
    version: '7.2',
    connection: {
        host: "localhost",
        user: "root",
        password: "Navgurukul123#@!",
        database: "Admin"
    }
})



// Create the "User" table
knex.schema.hasTable("users").then((exists) => {
    if (!exists) {
        return knex.schema.createTable("users", (table) => {
            table.increments("id").primary();
            table.string("name", 100);
            table.enu("role", ['Admin', 'superAdmin', 'Basic']);
            table.string("email", 100).unique();
            table.string("password", 100);
        });
    }
});


// Create the "Feed" table
knex.schema.hasTable("feeds").then((exists) => {
    if (!exists) {
        return knex.schema.createTable("feeds", (table) => {
            table.increments("id").primary();
            table.string("name", 100).notNullable();
            table.string("url").notNullable();
            table.string("description", 200).notNullable();
        });
    }
});


knex.schema.hasTable("admin_feed_access").then((exists) => {
    if (!exists) {
        knex.schema.createTable("admin_feed_access", (table) => {
            table.increments("id").primary();
            table.string("admin_email").notNullable();
            table.integer("feed_id").notNullable();
            table.foreign("admin_email").references("email").inTable("users");
            table.foreign("feed_id").references("feed_id").inTable("feeds");
        })
            .then(() => {
                console.log("admin_feed_access table created successfully.");
            })
            .catch((error) => {
                console.error("Error creating admin_feed_access table:", error);
            })
    }
})



app.post("/api/user", async (req, res) => {
    try {
        let value = req.body.password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(value, salt);

        const data = await knex('users').where('role', req.body.role)
        console.log(data, 'dataaaa')
        if (data[0] && data[0].role === 'superAdmin') {
            console.log("superAdmin can exist once cannot be added again and also it is allready exists... ")
            res.send("superAdmin can exist once cannot be added again and also it is allready exists... ")
        } else {
            await knex("users").insert({
                name: req.body.name,
                role: req.body.role,
                email: req.body.email,
                password: hashedPassword
            })
                .then(() => {
                    console.log("successfully created.   ")
                    res.send("successfully created.  ")
                })
                .catch((error) => {
                    console.log("something went!   ")
                    res.send(error)
                })
        }
    } catch (error) {
        console.log("something went wrong!");
        res.send(error);
    }
})


app.post("/api/loginuser", async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await knex("users").where("email", email).first();
        if (!user) {
            console.log("Invalid email or password.");
            return res.status(401).send("Invalid email or password.");
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            console.log("Invalid email or password.");
            return res.status(401).send("Invalid email or password.");
        }

        if (user.role !== "Admin" && user.role !== "superAdmin") {
            console.log("Unauthorized: You don't have permission to log in.");
            return res.status(403).send("Unauthorized: You don't have permission to log in.");
        }

        jwt.sign({ user }, "secret_key", (err, token) => {
            if (err) {
                console.log("Internal server error.");
                return res.status(500).send("Internal server error.");
            }
            res.cookie("token", token);
            console.log("Authentication successful.");
            res.send("Authentication successful.");
        });
    } catch (error) {
        console.log("Something went wrong!");
        res.status(500).send(error.message);
    }
});




app.post("/api/feed", verifyToken, (req, res) => {
    const user_token = req.cookies.token;
    jwt.verify(user_token, "secret_key", (err, authData) => {
        console.log(authData)
        if (err) {
            res.sendStatus(403);
            console.log(err)
        }
        else {
            const role = authData.user.role;
            console.log(role, "rrrr")
            if (role !== "Admin" && role !== "superAdmin") {
                res.status(403).send("You don't have permission to create feeds.");
            } else {
                const { name, url, description } = req.body;
                try {
                    // If the user is Super Admin, directly create the feed
                    if (role === "superAdmin") {
                        knex("feeds")
                            .insert({
                                name: name,
                                url: url,
                                description: description,
                            })
                            .then(() => {
                                console.log("Feed created successfully by Super Admin.");
                                res.send("Feed created successfully by Super Admin.");
                            })
                            .catch((error) => {
                                console.log("Something went wrong while creating a feed.");
                                res.status(500).send("Something went wrong while creating a feed.");
                            });
                    } else {
                        const adminEmail = authData.user[0].email;
                        const feedAccess = knex("admin_feed_access")
                            .where("admin_email", adminEmail)
                            .andWhere("feed_id", req.body.feedId);

                        if (feedAccess.length === 0) {
                            res.status(403).send("You don't have permission to create this feed.");
                        } else {
                            knex("feeds")
                                .insert({
                                    name: name,
                                    url: url,
                                    description: description,
                                })
                                .then(() => {
                                    console.log("Feed created successfully by Admin.");
                                    res.send("Feed created successfully by Admin.");
                                })
                                .catch((error) => {
                                    console.log("Something went wrong while creating a feed.");
                                    res.status(500).send("Something went wrong while creating a feed.");
                                });
                        }
                    }
                } catch (error) {
                    console.log("Something went wrong while creating a feed.");
                    res.status(500).send("Something went wrong while creating a feed.");
                }
            }
        }
    })
})


app.put("/updatefeed/:role", verifyToken, (req, res) => {
    // Check if the user is Super Admin
    const userRole = req.authData.user.role;
    console.log(userRole, "rrrrrrrrrr")
    if (userRole !== "superAdmin" && userRole !== "admin") {
        res.status(403).send("You don't have permission to update feeds.");
    } else {
        const feedId = parseInt(req.params.role);

        if (isNaN(feedId)) {
            return res.status(400).send("Invalid feed ID.");
        }

        // Check if the feed exists and the user has access to it
        knex("feeds")
            .where("id", feedId)
            .first()
            .then((feed) => {
                if (!feed) {
                    return res.status(404).send("Feed not found.");
                }

                if (userRole === "Admin" && !feed.adminAccess.includes(req.authData.user.email)) {
                    return res.status(403).send("You don't have access to update this feed.");
                }

                // Proceed with updating the feed
                const { name, url, description } = req.body;

                // Assuming you have a 'feeds' table in your database with columns: id, name, url, description
                return knex("feeds")
                    .where("id", feedId)
                    .update({
                        name: name,
                        url: url,
                        description: description
                    })
                    .then(() => {
                        console.log("Updated feed successfully.");
                        res.send("Updated feed successfully.");
                    })
                    .catch((err) => {
                        console.log(err);
                        res.status(500).send("Failed to update feed.");
                    });
            })
            .catch((err) => {
                console.log(err);
                res.status(500).send("Failed to fetch feed.");
            });
    }
});



app.put("/update/:role", verifyToken, async (req, res) => {
    const userRole = req.authData.user.role;
    if (userRole !== "superAdmin") {
        return res.status(403).send("You don't have permission to update users.");
    }

    const { name, role, email } = req.body;
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    try {
        const updatedRows = await knex("users")
            .where("role", req.params.role)
            .update({
                name: name,
                role: role,
                email: email,
                password: hashedPassword
            });

        if (updatedRows > 0) {
            console.log("User updated successfully.");
            res.send("User updated successfully.");
        } else {
            console.log("User with the specified role not found.");
            res.status(404).send("User with the specified role not found.");
        }
    } catch (error) {
        console.log("Error while updating user:", error);
        res.status(500).send("Error while updating user.");
    }
});



app.delete("/delete/:role", verifyToken, async (req, res) => {
    try {
        const userRole = req.authData.user.role;
        const roleToDelete = req.params.role;

        // Check if the user is Super Admin
        if (userRole !== "superAdmin") {
            return res.status(403).send("You don't have permission to delete roles.");
        }

        // Super Admin can delete any role except superAdmin itself
        if (roleToDelete === "superAdmin") {
            return res.status(400).send("Cannot delete superAdmin role.");
        }

        // Delete the role and associated users (if required)
        const deletedCount = await knex("users").where("role", roleToDelete).del();

        if (deletedCount > 0) {
            console.log(`Role '${roleToDelete}' and its associated users have been deleted.`);
            return res.send(`Role '${roleToDelete}' and its associated users have been deleted.`);
        } else {
            console.log(`Role '${roleToDelete}' not found or has already been deleted.`);
            return res.send(`Role '${roleToDelete}' not found or has already been deleted.`);
        }
    } catch (error) {
        console.log("Something went wrong while deleting the role.");
        res.status(500).send(error.message);
    }
});



app.delete("/deletefeed/:id", verifyToken, async (req, res) => {
    try {
        const userRole = req.authData.user.role;
        const useremail = req.body.email;

        // Check if the user is Super Admin or Admin
        if (userRole !== "Admin" && userRole !== "superAdmin") {
            return res.status(403).send("You don't have permission to delete feeds.");
        }

        // Super Admin can delete feeds
        if (userRole === "superAdmin") {
            const deletedRows = await knex("feeds")
                .where("id", req.params.id)
                .del();

            if (deletedRows > 0) {
                console.log("Feed deleted successfully by Super Admin.");
                return res.send("Feed deleted successfully by Super Admin.");
            } else {
                return res.status(404).send("Feed not found or you don't have permission to delete this feed.");
            }
        } else {
            // Admin can delete feeds if they have access to do so
            const feedAccess = await knex("admin_feed_access")
                .where("admin_email", useremail)
                .andWhere("feed_id", req.params.feedId);

            if (!feedAccess || feedAccess.length === 0) {
                return res.status(403).send("You don't have permission to delete this feed.");
            }

            const deletedRows = await knex("feeds")
                .where("id", req.params.id)
                .andWhere("email", useremail)
                .del();

            if (deletedRows > 0) {
                console.log("Feed deleted successfully by Admin.");
                return res.send("Feed deleted successfully by Admin.");
            } else {
                return res.status(404).send("Feed not found or you don't have permission to delete this feed.");
            }
        }
    } catch (error) {
        console.log("Something went wrong while deleting the feed.");
        res.status(500).send(error.message);
    }
});



app.get("/logs", verifyToken, (req, res) => {
    const role = req.authData.user.role;
    if (role !== "superAdmin") {
        return res.status(403).send("You don't have permission to access logs.");
    }

    try {
        const logs = fs.readFileSync(path.join(__dirname, "logs.txt"), "utf-8");
        res.send(logs);
    } catch (error) {
        console.log("Error while reading logs:", error);
        res.status(500).send("Error while reading logs.");
    }
});


app.listen(port, () => {
    console.log(`your port is running ${port}`)
})