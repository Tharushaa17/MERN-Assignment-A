import express from "express";
import { deleteUser, getUser, updateUser } from "../controllers/user.controllers.js";
import { verifyToken } from "../utils/verifyUser.js";
const router = express.Router();

router.post('/update/:id', verifyToken, updateUser);
router.delete('/delete/:id', verifyToken, deleteUser);
router.get('/get-username', getUser);

export default router;