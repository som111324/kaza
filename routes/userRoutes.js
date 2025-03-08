const express = require("express");
const { signup, signin, updateProfile } = require("../controllers/userController");
const authMiddleware = require("../middlewares/authMiddleware");

const router = express.Router();

router.post("/signup", signup);
router.post("/signin", signin);
router.put("/profile", authMiddleware, updateProfile);

module.exports = router;
