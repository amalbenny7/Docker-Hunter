const Joi = require("joi");
const createHttpError = require("http-errors");
const Validators = require("../validators");

module.exports = (validator) => {
  if (!Validators.hasOwnProperty(validator))
    throw new Error(`'${validator}' validator is not exist`);

  return async (req, res, next) => {
    try {
      const validated = await Validators[validator].validateAsync(req.body);
      req.body = validated;
      next();
    } catch (err) {
      return res.status(400).json({ message: err.message, status: false });
    }
  };
};
