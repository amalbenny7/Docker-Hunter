import React, { useState, useEffect } from "react";
import { DragDropContext } from "react-beautiful-dnd";
import Column from "./Column";
import { useDispatch, useSelector } from "react-redux";
import { getAllIssues } from "../../redux/Features/Issue/getIssuesSlice";
import { updateIssue } from "../../redux/Features/Issue/updateIssueSlice";

export default function Index() {
  const [openItems, setOpenItems] = useState([]);
  const [inProgressItems, setInProgressItems] = useState([]);
  const [reviewItems, setReviewItems] = useState([]);
  const [doneItems, setDoneItems] = useState([]);
  const dispatch = useDispatch();

  const { issues } = useSelector((store) => store.getIssue);

  const { issue } = useSelector((store) => store.createIssue);

  useEffect(() => {
    const getIssues = async () => {
      const accessToken = localStorage.getItem("accessToken");
      await dispatch(getAllIssues(accessToken));
    };

    getIssues();
  }, [issue]);

  useEffect(() => {
    if (issues.length === 0) return;

    setOpenItems(sortIssuesByStatus(issues, "open"));

    setInProgressItems(sortIssuesByStatus(issues, "In progress"));

    setReviewItems(sortIssuesByStatus(issues, "Review"));

    setDoneItems(sortIssuesByStatus(issues, "Done"));
  }, [issues]);

  const sortIssuesByStatus = (array, status) => {
    return array.filter(
      (item) => item.status.toLowerCase() === status.toLowerCase()
    );
  };

  const makeUpdateIssueRequest = ({ issueKey, updatedIssue }) => {
    const accessToken = localStorage.getItem("accessToken");
    let success;
    dispatch(
      updateIssue({
        accessToken: accessToken,
        issueKey: issueKey,
        updatedIssue: updatedIssue,
      })
    ).then((res) => {
      console.log(res);
      success = res.payload.data.status;
    });
    return success;
  };

  const handleDragEnd = (result) => {
    const { destination, source, draggableId } = result;

    if (source.droppableId == destination?.droppableId) return;

    // GET ITEM
    const task = findItemById(draggableId, [
      ...openItems,
      ...inProgressItems,
      ...reviewItems,
      ...doneItems,
    ]);

    //ADD ITEM
    if (destination.droppableId == 1) {
      const success = makeUpdateIssueRequest({
        issueKey: task.issueKey,
        updatedIssue: { status: "OPEN" },
      });
      if (success) {
        return;
      }
      setOpenItems([{ ...task, status: "Open" }, ...openItems]);
    }
    if (destination.droppableId == 2) {
      const success = makeUpdateIssueRequest({
        issueKey: task.issueKey,
        updatedIssue: { status: "IN PROGRESS" },
      });
      if (success) {
        return;
      }
      setInProgressItems([
        { ...task, status: "In progress" },
        ...inProgressItems,
      ]);
    }
    if (destination.droppableId == 3) {
      const success = makeUpdateIssueRequest({
        issueKey: task.issueKey,
        updatedIssue: { status: "REVIEW" },
      });
      if (success) {
        return;
      }
      setReviewItems([{ ...task, status: "Review" }, ...reviewItems]);
    }
    if (destination.droppableId == 4) {
      const success = makeUpdateIssueRequest({
        issueKey: task.issueKey,
        updatedIssue: { status: "DONE" },
      });
      if (success) {
        return;
      }
      setDoneItems([{ ...task, status: "Done" }, ...doneItems]);
    }

    //REMOVE FROM SOURCE ARRAY
    if (source.droppableId == 1) {
      setOpenItems(removeItemById(draggableId, openItems));
    }
    if (source.droppableId == 2) {
      setInProgressItems(removeItemById(draggableId, inProgressItems));
    }
    if (source.droppableId == 3) {
      setReviewItems(removeItemById(draggableId, reviewItems));
    }
    if (source.droppableId == 4) {
      setDoneItems(removeItemById(draggableId, doneItems));
    }
  };

  function findItemById(issueKey, array) {
    const lowerCaseIssueKey = issueKey.toLowerCase();
    return array.find(
      (item) => item.issueKey.toLowerCase() === lowerCaseIssueKey
    );
  }

  function removeItemById(issueKey, array) {
    const lowerCaseIssueKey = issueKey.toLowerCase();
    return array.filter(
      (item) => item.issueKey.toLowerCase() !== lowerCaseIssueKey
    );
  }

  return (
    <DragDropContext onDragEnd={handleDragEnd} className="h-full">
      <h2 className=" text-lg text-secondary py-4 font-medium">
        PROGRESS BOARD
      </h2>

      <div className="flex justify-between items-center gap-2">
        <Column title={"Open"} tasks={openItems} id={"1"} />
        <Column title={"In Progress"} tasks={inProgressItems} id={"2"} />
        <Column title={"Review"} tasks={reviewItems} id={"3"} />
        <Column title={"Done"} tasks={doneItems} id={"4"} />
      </div>
    </DragDropContext>
  );
}
