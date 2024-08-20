import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";

const initialState = {
  status: false,
  isfetching: false,
  error: null,
  issues: [],
  issue: {},
};

export const getAllIssues = createAsyncThunk(
  "issue/getAll",
  async (accessToken, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: "/issue",
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

export const getIssue = createAsyncThunk(
  "issue/getById",
  async ({ accessToken, issueKey }, thunkAPI) => {
    try {
      const response = await makeAPICall({
        url: `/issue/${issueKey}`,
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

export const getIssuesSlice = createSlice({
  name: "getIssues",
  initialState,
  reducers: {
    resetState(state, payload) {
      state.status = false;
    },
    updateFetchedIssueDesc(state, { payload }) {
      state.issue.description = payload;
    },
    updateFetchedIssueSumm(state, { payload }) {
      state.issue.summary = payload;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(getAllIssues.pending, (state, actions) => {
        state.isfetching = true;
        state.error = null;
        state.status = null;
      })
      .addCase(getAllIssues.fulfilled, (state, actions) => {
        state.isfetching = false;
        state.status = "succeeded";
        state.issues = actions.payload?.data.issues;
      })
      .addCase(getAllIssues.rejected, (state, { payload, error }) => {
        console.log(payload);
        state.isfetching = false;
        state.status = "failed";
        state.issues = [];
        state.error = payload ? payload.data.message : error.message;
      });
    builder
      .addCase(getIssue.pending, (state, actions) => {
        state.isfetching = true;
        state.error = null;
        state.status = null;
      })
      .addCase(getIssue.fulfilled, (state, actions) => {
        state.isfetching = false;
        state.status = "succeeded";
        state.issue = actions.payload?.data.issue;
      })
      .addCase(getIssue.rejected, (state, { payload, error }) => {
        state.isfetching = false;
        state.status = "failed";
        state.issue = {};
        state.error = payload ? payload.data.message : error.message;
      });
  },
});

export const { resetState, updateFetchedIssueDesc, updateFetchedIssueSumm } =
  getIssuesSlice.actions;

export default getIssuesSlice.reducer;
