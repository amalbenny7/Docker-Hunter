import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";
import { addUsername } from "../Auth/authSlice";

const initialState = {
  user: {
    usernameIsAvailable: false,
    username: null,
    usernameAdded: false,
  },
  isLoading: false,
  error: null,
  status: null,
};

export const checkUsernameIsAvailable = createAsyncThunk(
  "createUsername/checkUsernameIsAvailable",
  async (data, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: "/user/checkUsername",
        method: "post",
        data: data,
      });
      return { ...response, username: data.username };
    } catch (err) {
      if (!err.response) {
        throw err;
      }
      return thunkAPI.rejectWithValue(err.response);
    }
  }
);

export const submitUsername = createAsyncThunk(
  "createUsername/submitUsername",
  async (data, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: "/user/addUsername",
        method: "put",
        data: data,
      });
      thunkAPI.dispatch(addUsername({ username: data.username }));
      return { ...response, username: data.username };
    } catch (err) {
      if (!err.response) {
        throw err;
      }
      return thunkAPI.rejectWithValue(err.response);
    }
  }
);

const usernameSlice = createSlice({
  name: "createUsername",
  initialState: initialState,
  reducers: {
    resetError(state, actions) {
      state.error = null;
    },
    resetUsernameIsAvailable(state, actions) {
      state.user.usernameIsAvailable = false;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(checkUsernameIsAvailable.pending, (state, actions) => {
        state.isLoading = true;
        state.status = "loading";
      })
      .addCase(checkUsernameIsAvailable.fulfilled, (state, { payload }) => {
        state.status = "succeeded";
        state.isLoading = false;
        state.error = null;
        state.user.usernameIsAvailable = payload.data.isAvailable;
        state.user.username = payload.username;
      })
      .addCase(
        checkUsernameIsAvailable.rejected,
        (state, { payload, error }) => {
          state.isLoading = false;
          state.status = "failed";
          state.user.usernameIsAvailable = payload.data.isAvailable;
          state.error = payload ? payload.data.message : error.message;
        }
      );
    builder
      .addCase(submitUsername.pending, (state, actions) => {
        state.isLoading = true;
        state.status = "loading";
        state.user.usernameAdded = false;
      })
      .addCase(submitUsername.fulfilled, (state, { payload }) => {
        state.status = "succeeded";
        state.isLoading = false;
        state.error = null;
        state.user.username = payload.data.username;
        state.user.usernameAdded = true;
      })
      .addCase(submitUsername.rejected, (state, { payload, error }) => {
        state.user.usernameAdded = true;
        state.isLoading = false;
        state.status = "failed";
        state.error = payload ? payload.data.message : error.message;
      });
  },
});

export const { resetError, resetUsernameIsAvailable } = usernameSlice.actions;

export default usernameSlice.reducer;
