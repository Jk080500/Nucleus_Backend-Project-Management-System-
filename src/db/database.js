import mongoose from "mongoose";

const connectDatabase = async () => {
  try {
    await mongoose.connect(process.env.DB_URL);
    console.log("✅ MongoDB Connected");
  } catch (error) {
    console.error(`❌ MongoDb Connection Error : ${error}`);
    process.exit(1);
  }
};

export default connectDatabase;
