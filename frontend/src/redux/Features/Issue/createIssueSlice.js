import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";

const initialState = {
  status: false,
  isCreating: false,
  error: null,
  issue: {},
};

export const createIssue = createAsyncThunk(
  "issue/create",
  async ({ accessToken, issueDetails }, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: "/issue/create",
        method: "post",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        data: issueDetails,
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

export const createIssueSlice = createSlice({
  name: "create",
  initialState,
  reducers: {
    resetState(state, payload) {
      state.status = false;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(createIssue.pending, (state, actions) => {
        state.isCreating = true;
        state.error = null;
        state.status = null;
      })
      .addCase(createIssue.fulfilled, (state, actions) => {
        state.isCreating = false;
        state.status = "succeeded";
        state.issue = actions.payload?.data;
      })
      .addCase(createIssue.rejected, (state, { payload, error }) => {
        state.isCreating = false;
        state.status = "failed";
        state.issue = {};
        state.error = payload ? payload.data.message : error.message;
      });
  },
});

export const { resetState } = createIssueSlice.actions;

export default createIssueSlice.reducer;
