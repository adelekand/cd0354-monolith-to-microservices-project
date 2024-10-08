import { Router, Request, Response } from "express";

import { User } from "../models/User";
import * as c from "../../../../config/config";

import * as bcrypt from "bcrypt";
import * as jwt from "jsonwebtoken";
import { NextFunction } from "connect";

import * as EmailValidator from "email-validator";
import { config } from "bluebird";

const router: Router = Router();

async function generatePassword(plainTextPassword: string): Promise<string> {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  return await bcrypt.hash(plainTextPassword, salt);
}

async function comparePasswords(
  plainTextPassword: string,
  hash: string
): Promise<boolean> {
  return await bcrypt.compare(plainTextPassword, hash);
}

function generateJWT(user: User): string {
  return jwt.sign(user.short(), c.config.jwt.secret);
}

export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.headers || !req.headers.authorization) {
    res.status(401).send({ message: "No authorization headers." });
    return; // Ensure that you return here to stop further execution
  }

  const tokenBearer = req.headers.authorization.split(" ");
  if (tokenBearer.length !== 2) {
    res.status(401).send({ message: "Malformed token." });
    return;
  }

  const token = tokenBearer[1];
  jwt.verify(token, c.config.jwt.secret, (err, decoded) => {
    if (err) {
      res.status(500).send({ auth: false, message: "Failed to authenticate." });
      return;
    }
    next(); // Call `next()` only if verification is successful
  });
}

router.get(
  "/verification",
  requireAuth,
  async (req: Request, res: Response) => {
    res.status(200).send({ auth: true, message: "Authenticated." });
  }
);

router.post("/login", async (req: Request, res: Response) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !EmailValidator.validate(email)) {
    res
      .status(400)
      .send({ auth: false, message: "Email is required or malformed." });
  }

  if (!password) {
    res.status(400).send({ auth: false, message: "Password is required." });
  }

  const user = await User.findByPk(email);
  if (!user) {
    res.status(401).send({ auth: false, message: "User was not found.." });
  }

  const authValid = await comparePasswords(password, user.passwordHash);

  if (!authValid) {
    res.status(401).send({ auth: false, message: "Password was invalid." });
  }

  const jwt = generateJWT(user);
  res.status(200).send({ auth: true, token: jwt, user: user.short() });
});

router.post("/", async (req: Request, res: Response) => {
  const email = req.body.email;
  const plainTextPassword = req.body.password;

  if (!email || !EmailValidator.validate(email)) {
    res
      .status(400)
      .send({ auth: false, message: "Email is missing or malformed." });
  }

  if (!plainTextPassword) {
    res.status(400).send({ auth: false, message: "Password is required." });
  }

  const user = await User.findByPk(email);
  if (user) {
    res.status(422).send({ auth: false, message: "User already exists." });
  }

  const generatedHash = await generatePassword(plainTextPassword);

  const newUser = await new User({
    email: email,
    passwordHash: generatedHash,
  });

  const savedUser = await newUser.save();

  const jwt = generateJWT(savedUser);
  res.status(201).send({ token: jwt, user: savedUser.short() });
});

router.get("/", async (req: Request, res: Response) => {
  res.send("auth");
});

export const AuthRouter: Router = router;
