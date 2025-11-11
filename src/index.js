import "dotenv/config";
import app from "./app.js";
import connectDatabase from "./db/database.js";

const PORT = process.env.PORT || 3000;

connectDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server is running at Port  http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error(`Database Connect Error `, err);
  });
