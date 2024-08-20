const Joi = require("joi");
const { joiPasswordExtendCore } = require("joi-password");
const joiPassword = Joi.extend(joiPasswordExtendCore);

const signupSchema = Joi.object({
  email: Joi.string().email().lowercase().required(),
  password: joiPassword
    .string()
    .minOfSpecialCharacters(1)
    .minOfLowercase(1)
    .minOfUppercase(1)
    .minOfNumeric(1)
    .noWhiteSpaces()
    .min(8)
    .required(),
  confirmPassword: Joi.any().valid(Joi.ref("password")).required(),
});

module.exports = signupSchema;
