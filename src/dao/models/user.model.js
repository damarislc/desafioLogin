import mongoose from "mongoose";

/**
 * Modelo para la coleccion de users
 */
const usersCollection = "users";

const userSchema = new mongoose.Schema({
  name: String,
  lastname: String,
  email: String,
  age: Number,
  password: String,
});

const userModel = mongoose.model(usersCollection, userSchema);

export default userModel;
