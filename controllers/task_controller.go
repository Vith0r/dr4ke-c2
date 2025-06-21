package controllers

import (
	"dr4ke-c2/server/database"
	"dr4ke-c2/server/utils"
	"net/http"
)

type TaskController struct {
	store database.Store
}

func NewTaskController(store database.Store) *TaskController {
	return &TaskController{
		store: store,
	}
}
func (c *TaskController) GetTaskHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	clientID := r.URL.Query().Get("clientId")
	taskID := r.URL.Query().Get("taskId")
	if clientID == "" || taskID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID and Task ID are required")
		return
	}
	history, err := c.store.GetTaskHistory(clientID, taskID)
	if err != nil {
		c.handleTaskError(w, err)
		return
	}
	utils.RespondWithJSON(w, http.StatusOK, history)
}
func (c *TaskController) GetClientTaskHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		utils.RespondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	clientID := r.URL.Query().Get("clientId")
	if clientID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Client ID is required")
		return
	}
	if err := c.validateClient(clientID); err != nil {
		c.handleClientError(w, err)
		return
	}
	history, err := c.store.GetClientTaskHistory(clientID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve task history")
		return
	}
	utils.RespondWithJSON(w, http.StatusOK, history)
}
func (c *TaskController) validateClient(clientID string) error {
	_, err := c.store.GetClient(clientID)
	return err
}
func (c *TaskController) handleTaskError(w http.ResponseWriter, err error) {
	switch err {
	case database.ErrTaskNotFound:
		utils.RespondWithError(w, http.StatusNotFound, "Task history not found")
	default:
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve task history")
	}
}
func (c *TaskController) handleClientError(w http.ResponseWriter, err error) {
	switch err {
	case database.ErrClientNotFound:
		utils.RespondWithError(w, http.StatusNotFound, "Client not found")
	default:
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to check client")
	}
}
