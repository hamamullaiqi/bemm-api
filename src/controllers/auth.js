const { user } = require("../../models");

const Joi = require("joi");

const bcrypt = require("bcrypt");

const jwt = require("jsonwebtoken");

exports.register = async (req, res) => {
	const schema = Joi.object({
		fullname: Joi.string().min(5).required(),
		email: Joi.string().email().min(5).required(),
		password: Joi.string().min(6).required(),
	});

	const { error } = schema.validate(req.body);

	if (error)
		return res.status(400).send({
			error: {
				message: error.details[0].message,
			},
		});

	try {
		//time bcrypt
		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(req.body.password, salt);

		//validate user exits
		const userExist = await user.findOne({
			where: {
				email: req.body.email,
			},
		});

		if (!userExist) {
			const newUser = await user.create({
				fullname: req.body.fullname,
				email: req.body.email,
				password: hashedPassword,
			});
			const token = jwt.sign({ id: newUser.id }, process.env.TOKEN_KEY);
			res.status(201).send({
				status: "success",
				message: "Register Succeess",
				data: {
					user: {
						// id: newUser.id,
						fullname: newUser.fullname,
						email: newUser.email,
						image: newUser.image,
						token,
					},
				},
			});
		} else {
			return res.status(409).send({
				error: {
					message: "User already exists",
				},
			});
		}
	} catch (error) {
		console.log(error);
		res.status(500).send({
			status: "failed",
			message: "Server Error",
		});
	}
};

exports.login = async (req, res) => {
	const schema = Joi.object({
		email: Joi.string().email().min(5).required(),
		password: Joi.string().min(6).required(),
	});

	const { error } = schema.validate(req.body);

	if (error)
		return res.status(400).send({
			message: error.details[0].message,
		});

	try {
		const userExist = await user.findOne({
			where: {
				email: req.body.email,
			},
			attributes: {
				exclude: ["createdAt", "updateAt"],
			},
		});

		if (!userExist) {
			return res.status(400).send({
				status: "failed",
				message: "email is not registered, Please Sign Up",
			});
		}

		const isValid = await bcrypt.compare(req.body.password, userExist.password);

		if (!isValid) {
			return res.status(400).send({
				status: "failed",
				message: "email & password not match",
			});
		}

		// if(userExist.password !== req.body.password){
		//     return res.status(400).send({
		//         status: "failed",
		//         message: "email & password not match"
		//     })
		// }

		const token = jwt.sign({ id: userExist.id }, process.env.TOKEN_KEY);

		res.status(200).send({
			status: "success",
			message: "Login Success",
			data: {
				user: {
					// id: userExist.id,
					fullname: userExist.fullname,
					email: userExist.email,
					image: userExist.image,
					token,
				},
			},
		});
	} catch (error) {
		console.log(error);
		res.status(500).send({
			status: "failed",
			message: "Server Error",
		});
	}
};

exports.loginGoogle = async (req, res) => {
	try {
		const userExist = await user.findOne({
			where: {
				email: req.body.email,
			},
		});

		if (!userExist) {
			const newUser = await user.create({
				fullname: req.body.fullname,
				email: req.body.email,
				image : req.body.image
				// password: hashedPassword,
			});
			const token = jwt.sign({ id: newUser.id }, process.env.TOKEN_KEY);
			res.status(200).send({
				status: "success",
				message: "Register Succeess",
				data: {
					user: {
						// id: newUser.id,
						fullname: newUser.fullname,
						email: newUser.email,
						image: newUser.image,
						token,
					},
				},
			});
		} else {
			const token = jwt.sign({ id: userExist.id }, process.env.TOKEN_KEY);

			res.status(200).send({
				status: "success",
				message: "Login Success",
				data: {
					user: {
						// id: userExist.id,
						fullname: userExist.fullname,
						email: userExist.email,
						image: userExist.image,
						token,
					},
				},
			});
		}
	} catch (error) {
		console.log(error);
		res.status({
			status: "failed",
			message: "Server Error",
		});
	}
};
