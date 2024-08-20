import React from "react";
import { setIsModalOpen } from "../../redux/Features/Modal/modalSlice";
import { useDispatch, useSelector } from "react-redux";
import { MdClose } from "react-icons/md";
import Button from "../../Ui/Button";
import Spinner from "../../Ui/Spinner/Spinner";

const Modal = ({
  children,
  className,
  onClickFooterButton,
  loading,
  onModalClose,
}) => {
  const { isOpen } = useSelector((store) => store.modal);
  const dispatch = useDispatch();

  const onClose = () => {
    dispatch(setIsModalOpen({ isOpen: false }));
    if (onModalClose) {
      onModalClose();
    }
  };

  return (
    <>
      {isOpen && (
        <div className="fixed inset-0 z-50 overflow-auto bg-black bg-opacity-50 flex items-center justify-center">
          <div
            className={`relative bg-white rounded max-w-[800px] overflow-y-scroll ${className} column`}
          >
            <ModalHeader onClick={onClose} title="Create Issue" />
            <div className=" p-4 mb-10">{children}</div>

            <ModalFooter
              onClickFooterButton={onClickFooterButton}
              loading={loading}
            />
          </div>
        </div>
      )}
    </>
  );
};

export default Modal;

const ModalCloseButton = ({ onClick }) => {
  return (
    <button className=" text-gray-600" onClick={onClick}>
      <MdClose className=" text-buttonPrimary h-7 w-7" />
    </button>
  );
};

const ModalHeader = ({ title, onClick }) => {
  return (
    <div className=" sticky top-0 z-20 bg-white w-full p-4">
      <div className="flex justify-between items-center py-2">
        <div>
          <h1 className=" text-xl font-medium text-buttonPrimary">{title}</h1>
        </div>
        <div className="flex items-center">
          <ModalCloseButton onClick={onClick} />
        </div>
      </div>
    </div>
  );
};

const ModalFooter = ({ onClickFooterButton, loading }) => {
  return (
    <div className=" bg-white w-full sticky bottom-0 left-0 z-20 p-4 custom-shadow">
      <div className=" text-end">
        <Button
          isButton={true}
          onClick={onClickFooterButton}
          disabled={loading}
        >
          {loading ? <Spinner className="mx-4" /> : "Create"}
        </Button>
      </div>
    </div>
  );
};
