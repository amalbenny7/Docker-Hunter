import axios from "axios";
import { enqueueSnackbar } from "notistack";

const timeout = function (s) {
  return new Promise(function (_, reject) {
    setTimeout(function () {
      reject(new Error(`Request took too long! Timeout after ${s} second`));
    }, s * 1000);
  });
};

const makeAPICall = async (options) => {
  axios.defaults.headers.common[
    "Authorization"
  ] = `Bearer ${localStorage.getItem("accessToken")}`;
  try {
    axios.defaults.baseURL = "http://localhost:8080";

    const fetchPro = axios({ ...options });

    const response = await Promise.race([fetchPro, timeout(15)]);

    return response;
  } catch (err) {
    if (err.response && err.response.data) {
      enqueueSnackbar(err.response.data.message, {
        variant: "error",
        autoHideDuration: 4000,
      });
    } else {
      enqueueSnackbar(err.message, {
        variant: "error",
        autoHideDuration: 4000,
      });
    }

    throw err;
  }
};

export default makeAPICall;
