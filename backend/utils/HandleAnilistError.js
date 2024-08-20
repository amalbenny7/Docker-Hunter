const HandleAnilistError = (err, res) => {
  if (err.response) {
    return res
      .status(err.response.status)
      .json({ message: err.response.data.errors[0].message });
  }
  if (err.request) {
    return res
      .status(500)
      .send({ message: "No response from server", status: false });
  }
  return res.status(500).send({ error: err.message });
};

module.exports = HandleAnilistError;
