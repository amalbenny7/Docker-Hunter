import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";

const initialState = {
  status: false,
  isFetching: false,
  error: null,
  comments: [],
  isAdding: false,
};

export const getComments = createAsyncThunk(
  "issue/comments",
  async ({ accessToken, issueKey }, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: `/issue/${issueKey}/comments`,
        method: "get",
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

export const addComment = createAsyncThunk(
  "issue/comments/add",
  async ({ accessToken, issueKey, data }, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: `/issue/${issueKey}/comments`,
        method: "post",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        data: data,
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

export const commentsSlice = createSlice({
  name: "comments",
  initialState,
  reducers: {
    resetState(state, payload) {
      state.status = false;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(getComments.pending, (state, actions) => {
        state.isFetching = true;
        state.error = null;
        state.status = null;
      })
      .addCase(getComments.fulfilled, (state, actions) => {
        state.isFetching = false;
        state.status = "succeeded";
        state.comments = actions.payload.data.comments;
      })
      .addCase(getComments.rejected, (state, { payload, error }) => {
        state.isFetching = false;
        state.status = "failed";
        state.error = payload ? payload.data.message : error.message;
      });
    builder
      .addCase(addComment.pending, (state, actions) => {
        state.isAdding = true;
        state.error = null;
        state.status = null;
      })
      .addCase(addComment.fulfilled, (state, actions) => {
        state.isAdding = false;
        state.status = "succeeded";
        state.comments = [actions.payload.data.data, ...state.comments];
      })
      .addCase(addComment.rejected, (state, { payload, error }) => {
        state.isAdding = false;
        state.status = "failed";
        state.error = payload ? payload.data.message : error.message;
      });
  },
});

export const { resetState } = commentsSlice.actions;

export default commentsSlice.reducer;
