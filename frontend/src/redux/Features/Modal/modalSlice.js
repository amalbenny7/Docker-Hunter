import { createSlice } from "@reduxjs/toolkit";

const initialState = {
  isOpen: false,
  method: null,
};

const modal = createSlice({
  name: "modal",
  initialState,
  reducers: {
    setIsModalOpen(state, { payload }) {
      state.isOpen = payload.isOpen;
    },
    onclickModalFooterButton(state, { payload }) {
      state.method();
    },
    setOnClickMethod(state, { payload }) {
      state.method = payload.method;
    },
  },
});

export const { setIsModalOpen, onclickModalFooterButton, setOnClickMethod } =
  modal.actions;

export default modal.reducer;
