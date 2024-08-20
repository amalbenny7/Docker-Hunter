import React, { useEffect, useState } from "react";
import TextInput from "../../Ui/Form/TextInput";
import TextEditor from "../../Ui/Form/TextEditor";
import _ from "lodash";

function CreateIssue(props) {
  const { onChangeInEditor, onChangeSummary, formValues, error } = props;

  return (
    <div className="w-full">
      <form className=" space-y-2">
        <div className=" space-y-1">
          <label htmlFor="summary" className="text-sm text-labelColor">
            Summary <span className=" text-red-500 ">*</span>
          </label>
          <TextInput
            name="summary"
            value={formValues.summary}
            type="text"
            onChange={onChangeSummary}
            error={_.isEmpty(error) ? null : error.summary}
          />
        </div>
        <div className=" space-y-1">
          <label htmlFor="description" className="text-sm text-labelColor">
            Description
          </label>
          <TextEditor
            value={formValues.description}
            onChange={onChangeInEditor}
            className="w-full !rounded h-[300px] "
            placeholder="Write description"
          />
        </div>
      </form>
    </div>
  );
}

export default CreateIssue;
