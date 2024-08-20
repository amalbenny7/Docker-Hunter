import { Avatar } from "antd";
import React, { useState } from "react";
import TextInput from "../../Ui/Form/TextInput";
import Comments from "./Comments";
import TextEditor from "../../Ui/Form/TextEditor";
import Spinner from "../../Ui/Spinner/Spinner";
import Button from "../../Ui/Button";
import { useParams } from "react-router-dom";
import { useDispatch, useSelector } from "react-redux";
import {
  addComment,
  getComments,
} from "../../redux/Features/Comments/commentsSice";

const CommentSection = () => {
  const [editableCommentBox, setEditableCommentBox] = useState(false);
  const [comment, setComment] = useState("");

  const dispatch = useDispatch();
  const { issueKey } = useParams();

  const { comments, isFetching, isAdding } = useSelector(
    (store) => store.comments
  );
  const { user } = useSelector((store) => store.auth);

  useState(() => {
    const fetchComments = () => {
      const accessToken = localStorage.getItem("accessToken");
      dispatch(getComments({ accessToken: accessToken, issueKey: issueKey }));
    };

    fetchComments();
  }, []);

  const toggleCommentBox = () => {
    setEditableCommentBox((prevState) => !prevState);
    setComment("");
  };

  const onChangeCommentBox = (value) => {
    setComment(value);
  };

  console.log(user);

  const onClickSaveButton = () => {
    const accessToken = localStorage.getItem("accessToken");
    const commentData = {
      userId: user.userId,
      text: comment,
    };

    console.log(commentData);
    dispatch(
      addComment({
        data: commentData,
        accessToken: accessToken,
        issueKey: issueKey,
      })
    ).then((res) => {
      if (res.payload.data.status) {
        toggleCommentBox();
      }
    });
  };

  return (
    <div className=" w-full mb-12">
      {isFetching ? (
        <div className="w-full text-center">
          <Spinner className=" h-8 w-8" />
        </div>
      ) : (
        <>
          <div className=" w-full flex items-start gap-3 mb-3">
            <div className="">
              <Avatar size="large" src={"https://joesch.moe/api/v1/random"} />
            </div>
            <div className=" flex flex-col  gap-2 w-full">
              <Editor
                show={editableCommentBox}
                value={comment}
                toggleEditing={toggleCommentBox}
                onChange={onChangeCommentBox}
              />
              <ButtonContainers
                show={editableCommentBox}
                cancelAction={toggleCommentBox}
                onClickSave={onClickSaveButton}
                isAdding={isAdding}
              />
            </div>
          </div>
          <div className=" space-y-2">
            {comments?.length > 0 && renderComents(comments)}
          </div>
        </>
      )}
    </div>
  );
};

export default CommentSection;

const renderComents = (comments) => {
  return comments.map((comment, index) => (
    <Comments
      key={index}
      username={comment.userDetails.username}
      text={comment.text}
      timeStamp={comment.createdAt}
    />
  ));
};

const Editor = (props) => {
  const { show, value, toggleEditing, onChange } = props;
  return (
    <>
      {!show ? (
        <TextInput
          onClick={toggleEditing}
          classname="w-full"
          placeholder="Add a comment"
          name="comment"
          type="text"
          error={null}
        />
      ) : (
        <div className="">
          <div className="editor-container block">
            {show && (
              <TextEditor
                value={value}
                onChange={onChange}
                className="w-full !rounded h-auto inline-block"
              />
            )}
          </div>
        </div>
      )}
    </>
  );
};

const ButtonContainers = (props) => {
  const { show, cancelAction, onClickSave, isAdding } = props;
  return (
    <div className="">
      {show && (
        <div className=" flex items-center gap-2">
          <Button isButton={true} disabled={isAdding} onClick={onClickSave}>
            {isAdding ? <Spinner className="mx-3" /> : "Save"}
          </Button>
          <Button
            isButton={true}
            onClick={cancelAction}
            className="bg-transparent !text-buttonPrimary hover:bg-slate-100"
          >
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
};
