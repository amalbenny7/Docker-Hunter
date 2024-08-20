import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";

const initialState = {
  status: false,
  isDeleting: false,
  error: null,
};

export const deleteIssue = createAsyncThunk(
  "issue/delete",
  async ({ accessToken, issueKey, updatedIssue }, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: `/issue/${issueKey}`,
        method: "delete",
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

export const deleteIssueSlice = createSlice({
  name: "delete",
  initialState,
  reducers: {
    resetState(state, payload) {
      state.status = false;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(deleteIssue.pending, (state, actions) => {
        state.isDeleting = true;
        state.error = null;
        state.status = null;
      })
      .addCase(deleteIssue.fulfilled, (state, actions) => {
        state.isDeleting = false;
        state.status = "succeeded";
      })
      .addCase(deleteIssue.rejected, (state, { payload, error }) => {
        state.isDeleting = false;
        state.status = "failed";
        state.error = payload ? payload.data.message : error.message;
      });
  },
});

export const { resetState } = deleteIssueSlice.actions;

export default deleteIssueSlice.reducer;
