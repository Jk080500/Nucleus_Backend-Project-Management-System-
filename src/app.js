import express from "express";
import cors from "cors";
const app = express();

//Routes Import
import healthCheckRouter from "./routes/healthcheck.routes.js";
import authRouter from "./routes/auth.routes.js";

//app.use => express middlewares
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));

//Routes middlewares
app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

//CORS Configurations
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "https://localhost:1358",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

export default app;
