import { createSlice } from "@reduxjs/toolkit";

const initialState = {
  message: null,
  show: false,
};

const snackbar = createSlice({
  name: "snackbar",
  initialState,
  reducers: {
    showSnackBar(state, { payload }) {
      state.show = true;
      state.message = payload.message;
    },
    closeSnackBar(state) {
      state.show = false;
      state.message = null;
    },
  },
});

export const { showSnackBar, closeSnackBar } = snackbar.actions;

export default snackbar.reducer;
