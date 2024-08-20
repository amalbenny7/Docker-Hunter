import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";

const initialState = {
  user: {
    userId: null,
    username: null,
    isLoggedIn: false,
  },
  isLoading: false,
  error: null,
  status: null,
  formSubmitted: false,
  isGettingUserOrToken: false,
};

export const loginUser = createAsyncThunk(
  "auth/loginUser",
  async (loginData, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: "/user/login",
        method: "post",
        data: loginData,
      });
      return response;
    } catch (err) {
      if (!err.response) {
        throw err;
      }
      return thunkAPI.rejectWithValue(err.response);
    }
  }
);

export const signUpUser = createAsyncThunk(
  "auth/signUpUser",
  async (signUpData, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: "/user/signup",
        method: "post",
        data: signUpData,
      });
      return response;
    } catch (err) {
      if (!err.response) {
        throw err;
      }
      return thunkAPI.rejectWithValue(err.response);
    }
  }
);

export const getUser = createAsyncThunk(
  "auth/getUser",
  async (accessToken, thunkAPI) => {
    try {
      const response = await makeAPICall({
        method: "get",
        url: "/user/getUser",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      return response;
    } catch (err) {
      if (!err.response) {
        throw err;
      }
      return thunkAPI.rejectWithValue(err.response);
    }
  }
);

export const getRefreshToken = createAsyncThunk(
  "auth/getRefreshToken",
  async (refreshToken, thunkAPI) => {
    try {
      const response = await makeAPICall({
        method: "get",
        url: "/user/refresh-token",
        body: {
          refreshToken: refreshToken,
        },
      });
      return response;
    } catch (err) {
      if (!err.response) {
        throw err;
      }
      return thunkAPI.rejectWithValue(err.response);
    }
  }
);

const authSlice = createSlice({
  name: "auth",
  initialState,
  reducers: {
    addUsername(state, { payload }) {
      state.user.username = payload.username;
    },
    resetError(state, actions) {
      state.error = null;
    },
    logoutUser(state, { payload }) {
      localStorage.removeItem("accessToken");
      localStorage.removeItem("refreshToken");
      localStorage.removeItem("expiresAt");
      state.user.username = null;
      state.user.userId = null;
      state.user.isLoggedIn = false;
      state.status = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loginUser.pending, (state, action) => {
        state.isLoading = true;
        state.status = "loading";
        state.formSubmitted = false;
      })
      .addCase(loginUser.fulfilled, (state, { payload }) => {
        state.user.userId = payload.data.userId;
        state.user.username = payload.data.username;
        localStorage.setItem("accessToken", payload.data.accessToken);
        localStorage.setItem("refreshToken", payload.data.refreshToken);
        localStorage.setItem("expiresAt", payload.data.expiresAt);
        state.status = "succeeded";
        state.user.isLoggedIn = true;
        state.isLoading = false;
        state.error = null;
        state.formSubmitted = true;
      })
      .addCase(loginUser.rejected, (state, { payload, error }) => {
        state.isLoading = false;
        state.status = "failed";
        state.user.isLoggedIn = false;
        state.error = payload ? payload.data.message : error.message;
        state.formSubmitted = true;
      });
    builder
      .addCase(signUpUser.pending, (state, action) => {
        state.isLoading = true;
        state.status = "loading";
        state.formSubmitted = false;
      })
      .addCase(signUpUser.fulfilled, (state, { payload }) => {
        state.user.userId = payload.data.userId;
        localStorage.setItem("accessToken", payload.data.accessToken);
        localStorage.setItem("refreshToken", payload.data.refreshToken);
        localStorage.setItem("expiresAt", payload.data.expiresAt);
        state.status = "succeeded";
        state.user.isLoggedIn = true;
        state.isLoading = false;
        state.error = null;
        state.formSubmitted = true;
      })
      .addCase(signUpUser.rejected, (state, { payload, error }) => {
        state.isLoading = false;
        state.status = "failed";
        state.user.isLoggedIn = false;
        state.error = payload ? payload.data.message : error.message;
        state.formSubmitted = true;
      });

    builder
      .addCase(getUser.pending, (state, action) => {
        state.isGettingUserOrToken = true;
        state.status = "loading";
        state.user.isLoggedIn = false;
      })
      .addCase(getUser.fulfilled, (state, { payload }) => {
        state.user.userId = payload.data.userId;
        state.user.username = payload.data.username;
        state.user.isLoggedIn = true;
        state.status = "succeeded";
        state.isGettingUserOrToken = false;
        state.error = null;
      })
      .addCase(getUser.rejected, (state, { payload, error }) => {
        state.isGettingUserOrToken = false;
        state.user.isLoggedIn = false;
        state.status = "failed";
        state.error = payload ? payload.data.message : error.message;
      });
    builder
      .addCase(getRefreshToken.pending, (state, action) => {
        state.isGettingUserOrToken = true;
        state.status = "loading";
        state.user.isLoggedIn = false;
      })
      .addCase(getRefreshToken.fulfilled, (state, { payload }) => {
        localStorage.setItem("accessToken", payload.data.accessToken);
        localStorage.setItem("refreshToken", payload.data.refreshToken);
        localStorage.setItem("expiresAt", payload.data.expiresAt);
        state.status = "succeeded";
        state.user.isLoggedIn = true;
        state.isGettingUserOrToken = false;
        state.error = null;
      })
      .addCase(getRefreshToken.rejected, (state, { payload, error }) => {
        state.isGettingUserOrToken = false;
        state.user.isLoggedIn = false;
        state.status = "failed";
        state.error = payload ? payload.data.message : error.message;
      });
  },
});

export const { addUsername, resetError, logoutUser } = authSlice.actions;
export const user = (state) => state.user;
export default authSlice.reducer;
