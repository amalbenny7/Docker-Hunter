import React from "react";
import { Draggable } from "react-beautiful-dnd";
import { Avatar } from "antd";
import { Link } from "react-router-dom";

export default function Task({ task, index }) {
  const { _id, summary, issueKey } = task;
  return (
    <Draggable draggableId={issueKey} key={_id} index={index}>
      {(provided, snapshot) => (
        <div
          className={`border rounded p-2 mb-2 min-h-[90px] bg-white shadow-sm  ${
            snapshot.isDragging ? "bg-blue-100" : ""
          } flex flex-col h-full`}
          ref={provided.innerRef}
          {...provided.draggableProps}
          {...provided.dragHandleProps}
        >
          <div className="flex-1">
            <Link
              to={`/issue/${issueKey}`}
              className="text-base text-secondary"
            >
              {summary}
            </Link>
          </div>
          <div className="flex justify-between items-end">
            <div className="">
              <Link
                to={`/issue/${issueKey}`}
                className="text-xs text-[#44546F]"
              >
                {issueKey}
              </Link>
            </div>
            <div className="">
              <Avatar src={"https://joesch.moe/api/v1/random?key=" + _id} />
            </div>
          </div>
        </div>
      )}
    </Draggable>
  );
}

{
  /* <TaskBody id={task.id} title={task.title} /> */
}

const TaskBody = (props) => {
  const { id, title } = props;
  return (
    <div className="flex flex-col h-full justify-between ">
      <div className="flex-1">
        <h4 className="text-base text-secondary">{title}</h4>
      </div>
      <div className="flex justify-between items-center">
        <div className="mt-auto">
          <h5 className="text-xs text-[#44546F]">DEV-{id}</h5>
        </div>

        <div className="">
          <Avatar
            onClick={() => console.log(id)}
            src={"https://joesch.moe/api/v1/random?key=" + id}
          />
        </div>
      </div>
    </div>
  );
};
