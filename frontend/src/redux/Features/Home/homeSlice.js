import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import makeAPICall from "../../../Utils/makeAPICall";

const initialState = {
  home: {
    trendingAnimes: null,
    upComingAnimes: null,
    haveData: false,
  },
  status: false,
  isLoading: false,
  error: null,
};

export const getHomePageContents = createAsyncThunk(
  "home/getHomePageContents",
  async (thunkAPI) => {
    try {
      const response = await makeAPICall({
        method: "get",
        url: "/anime/home",
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

const homeSlice = createSlice({
  name: "home",
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(getHomePageContents.pending, (state, actions) => {
        state.isLoading = true;
        state.error = null;
        state.home.haveData = false;
        state.status = "loading";
      })
      .addCase(getHomePageContents.fulfilled, (state, { payload }) => {
        state.isLoading = false;
        state.status = "succeeded";
        state.home.trendingAnimes = payload.data.trendingAnimes.media;
        state.home.upComingAnimes = payload.data.upcomingAnimes.media;
        state.home.haveData = true;
      })
      .addCase(getHomePageContents.rejected, (state, { payload, error }) => {
        state.isLoading = false;
        state.status = "failed";
        state.error = payload ? payload.data.message : error.message;
        state.home.haveData = false;
      });
  },
});

export const upComingAnimes = (state) => state.home.home.upComingAnimes;
export const trendingAnimes = (state) => state.home.home.trendingAnimes;
export const haveHomeData = (state) => state.home.home.haveData;

export default homeSlice.reducer;
