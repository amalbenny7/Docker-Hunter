import { configureStore } from "@reduxjs/toolkit";
import authReducer from "../Features/Auth/authSlice";
import createUsernameReducer from "../Features/Username/UsernameSlice";
import snackbarSlice from "../Features/SnackBar/snackbarSlice";
import modalSlice from "../Features/Modal/modalSlice";
import createIssueReducer from "../Features/Issue/createIssueSlice";
import getIssuesReducer from "../Features/Issue/getIssuesSlice";
import updateIssueReducer from "../Features/Issue/updateIssueSlice";
import deleteIssueReducer from "../Features/Issue/deleteIssueSlice";
import commentsReducer from "../Features/Comments/commentsSice";

export default configureStore({
  reducer: {
    auth: authReducer,
    createUsername: createUsernameReducer,
    snackbar: snackbarSlice,
    modal: modalSlice,
    createIssue: createIssueReducer,
    getIssue: getIssuesReducer,
    updateIssue: updateIssueReducer,
    deleteIssue: deleteIssueReducer,
    comments: commentsReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false,
    }),
});
