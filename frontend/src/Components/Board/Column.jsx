import React from "react";
import Task from "./Task";
import "./scroll.css";
import { Droppable } from "react-beautiful-dnd";

export default function Column({ title, tasks, id }) {
  return (
    <div className="column w-[300px] h-[450px] overflow-y-scroll bg-boardBgColor rounded">
      <div className="sticky top-0 bg-boardBgColor z-10 py-4">
        <h2 className=" text-xs text-boardTextColor font-medium uppercase mx-4">
          {title}
        </h2>
      </div>

      <Droppable droppableId={id}>
        {(provided, snapshot) => (
          <div
            className="grow p-2 min-h-[100px]"
            ref={provided.innerRef}
            {...provided.droppableProps}
            isDraggingOver={snapshot.isDraggingOver}
          >
            {tasks?.map((task, index) => (
              <Task key={index} index={index} task={task} />
            ))}
            {provided.placeholder}
          </div>
        )}
      </Droppable>
    </div>
  );
}
