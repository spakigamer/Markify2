import mongoose from "mongoose";

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  googleId: String, 
});

const NoteSchema = new mongoose.Schema({
  email: String,
  title: String,
  description: String,
  marktext: String,
});

const User = mongoose.model("User", UserSchema);
const Note = mongoose.model("Note", NoteSchema);

export { User, Note };
