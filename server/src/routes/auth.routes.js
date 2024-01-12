import express from 'express';
const router = express.Router();
import { singOut, signin, singup } from '../controllers/auth.controller.js';

router.post('/sing-up', singup)
router.post('/sing-in', signin)
router.get('/sing-out', singOut)

export default router;