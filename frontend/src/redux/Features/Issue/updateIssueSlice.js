import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";

const initialState = {
  status: false,
  isUpdating: false,
  error: null,
  issue: {},
};

export const updateIssue = createAsyncThunk(
  "issue/update",
  async ({ accessToken, issueKey, updatedIssue }, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: `/issue/key/${issueKey}`,
        method: "put",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
        data: updatedIssue,
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

export const updateIssueSlice = createSlice({
  name: "update",
  initialState,
  reducers: {
    resetState(state, payload) {
      state.status = false;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(updateIssue.pending, (state, actions) => {
        state.isUpdating = true;
        state.error = null;
        state.status = null;
      })
      .addCase(updateIssue.fulfilled, (state, actions) => {
        state.isUpdating = false;
        state.status = "succeeded";
        state.issue = actions.payload?.data.issue;
      })
      .addCase(updateIssue.rejected, (state, { payload, error }) => {
        state.isUpdating = false;
        state.status = "failed";
        state.issue = {};
        state.error = payload ? payload.data.message : error.message;
      });
  },
});

export const { resetState } = updateIssueSlice.actions;

export default updateIssueSlice.reducer;
