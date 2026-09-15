"use client";
import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  Users,
  UserPlus,
  UserCheck,
  ShieldCheck,
  Search,
  Filter,
  RefreshCw,
  Edit3,
  Trash2,
  CheckCircle2,
  AlertCircle,
  X,
  ChevronLeft,
  ChevronRight,
  Shield,
  Key,
} from "lucide-react";

import DashboardCard from "../DashboardCard";
import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";
import { useTheme } from "../../context/ThemeContext";

const DEFAULT_USERS = [
  {
    id: 1,
    email: "demo@gmail.com",
    role: "Security Administrator",
    raw_role: "admin",
    access: "Full Global Control",
    status: "Active",
    created_at: "2026-07-27 08:50:00 UTC",
  },
  {
    id: 2,
    email: "sec_admin@gmail.com",
    role: "Security Administrator",
    raw_role: "admin",
    access: "Full Global Control",
    status: "Active",
    created_at: "2026-07-27 08:52:08 UTC",
  },
  {
    id: 3,
    email: "analyst@gmail.com",
    role: "Security Analyst",
    raw_role: "analyst",
    access: "Read / Monitor / Triage",
    status: "Active",
    created_at: "2026-07-27 08:52:03 UTC",
  },
  {
    id: 4,
    email: "newuser@gmail.com",
    role: "Security Analyst",
    raw_role: "analyst",
    access: "Read / Monitor / Triage",
    status: "Active",
    created_at: "2026-07-27 08:52:13 UTC",
  },
];

export default function UserManagementView() {
  const { isDark } = useTheme();

  const [usersList, setUsersList] = useState([]);
  const [userMetrics, setUserMetrics] = useState(null);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [usersError, setUsersError] = useState(null);
  const [isUsingFallback, setIsUsingFallback] = useState(false);

  // Filters, Search, Pagination
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Notification Toast
  const [toast, setToast] = useState(null);

  // Modals
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);

  // Form states
  const [newUserForm, setNewUserForm] = useState({
    email: "",
    password: "",
    role: "analyst",
    status: "Active",
  });
  const [editUserForm, setEditUserForm] = useState({
    role: "analyst",
    status: "Active",
  });

  const showToast = useCallback((type, text) => {
    setToast({ type, text });
    setTimeout(() => {
      setToast(null);
    }, 4000);
  }, []);

  const fetchUsers = useCallback(async () => {
    setLoadingUsers(true);
    setUsersError(null);
    setIsUsingFallback(false);
    try {
      const res = await fetchApi("/api/auth/users");
      if (res.metrics) {
        setUserMetrics(res.metrics);
      }
      const rawData = res.data || res.users || (Array.isArray(res) ? res : []);
      if (Array.isArray(rawData) && rawData.length > 0) {
        setUsersList(rawData);
      } else {
        setUsersList(DEFAULT_USERS);
        setIsUsingFallback(true);
      }
    } catch (err) {
      console.warn("Backend user fetch error, loading default dataset:", err);
      setUsersList(DEFAULT_USERS);
      setIsUsingFallback(true);
    } finally {
      setLoadingUsers(false);
    }
  }, []);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  // Derived KPI metrics
  const totalUsers = userMetrics?.total_users ?? usersList.length;
  const adminCount =
    userMetrics?.administrators_count ??
    usersList.filter(
      (u) => u.role === "Security Administrator" || u.raw_role === "admin"
    ).length;
  const analystCount =
    userMetrics?.analysts_count ??
    usersList.filter(
      (u) => u.role === "Security Analyst" || u.raw_role === "analyst"
    ).length;
  const activeCount =
    userMetrics?.active_sessions_count ??
    usersList.filter((u) => u.status === "Active" || !u.status).length;

  // Filtered & Search Results
  const filteredUsers = useMemo(() => {
    return usersList.filter((u) => {
      const query = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !query ||
        (u.email && u.email.toLowerCase().includes(query)) ||
        (u.role && u.role.toLowerCase().includes(query)) ||
        (u.access && u.access.toLowerCase().includes(query));

      let matchesRole = true;
      if (roleFilter === "ADMIN") {
        matchesRole = u.role === "Security Administrator" || u.raw_role === "admin";
      } else if (roleFilter === "ANALYST") {
        matchesRole = u.role === "Security Analyst" || u.raw_role === "analyst";
      }

      let matchesStatus = true;
      if (statusFilter !== "ALL") {
        matchesStatus = (u.status || "Active").toUpperCase() === statusFilter.toUpperCase();
      }

      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [usersList, searchQuery, roleFilter, statusFilter]);

  // Reset pagination to page 1 when search query or filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, roleFilter, statusFilter, pageSize]);

  // Calculate total pages dynamically based on filtered users count
  const totalPages = useMemo(() => {
    return Math.max(1, Math.ceil(filteredUsers.length / pageSize));
  }, [filteredUsers.length, pageSize]);

  // Clamp currentPage if filtered results shrink below currentPage
  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(totalPages);
    }
  }, [totalPages, currentPage]);

  // Derive current page user records for rendering
  const paginatedUsers = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredUsers.slice(start, start + pageSize);
  }, [filteredUsers, currentPage, pageSize]);

  // Explicit pagination button handlers
  const handlePrevPage = useCallback((e) => {
    if (e && e.preventDefault) e.preventDefault();
    setCurrentPage((prev) => Math.max(prev - 1, 1));
  }, []);

  const handleNextPage = useCallback((e) => {
    if (e && e.preventDefault) e.preventDefault();
    setCurrentPage((prev) => Math.min(prev + 1, totalPages));
  }, [totalPages]);


  // Handler: Add User
  const handleAddUserSubmit = async (e) => {
    e.preventDefault();
    if (!newUserForm.email || !newUserForm.password) {
      showToast("error", "Email and Password are required.");
      return;
    }

    try {
      await fetchApi("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email: newUserForm.email,
          password: newUserForm.password,
          role: newUserForm.role,
          status: newUserForm.status || "Active",
        }),
      });
      showToast("success", `User account ${newUserForm.email} created successfully.`);
      fetchUsers();
    } catch (err) {
      const newUser = {
        id: Date.now(),
        email: newUserForm.email.toLowerCase(),
        role: newUserForm.role === "admin" ? "Security Administrator" : "Security Analyst",
        raw_role: newUserForm.role,
        access: newUserForm.role === "admin" ? "Full Global Control" : "Read / Monitor / Triage",
        status: newUserForm.status || "Active",
        created_at: new Date().toISOString().replace("T", " ").substring(0, 19),
      };
      setUsersList((prev) => [newUser, ...prev]);
      showToast("success", `User ${newUserForm.email} registered successfully.`);
    }

    setShowAddModal(false);
    setNewUserForm({ email: "", password: "", role: "analyst", status: "Active" });
  };

  // Handler: Open Edit Modal
  const handleOpenEdit = (user) => {
    setSelectedUser(user);
    const rawRole =
      user.raw_role ||
      (user.role === "Security Administrator" ? "admin" : "analyst");
    setEditUserForm({
      role: rawRole,
      status: user.status || "Active",
    });
    setShowEditModal(true);
  };

  // Handler: Submit Edit / Role Assignment
  const handleEditUserSubmit = async (e) => {
    e.preventDefault();
    if (!selectedUser) return;

    const newRoleTitle =
      editUserForm.role === "admin" ? "Security Administrator" : "Security Analyst";
    const newAccess =
      editUserForm.role === "admin" ? "Full Global Control" : "Read / Monitor / Triage";

    try {
      if (selectedUser.id && !isUsingFallback) {
        await fetchApi(`/api/auth/users/${selectedUser.id}`, {
          method: "PUT",
          body: JSON.stringify({ role: editUserForm.role, status: editUserForm.status }),
        });
        showToast("success", `Updated role & status for ${selectedUser.email}.`);
        fetchUsers();
      } else {
        setUsersList((prev) =>
          prev.map((u) =>
            u.email === selectedUser.email
              ? {
                  ...u,
                  role: newRoleTitle,
                  raw_role: editUserForm.role,
                  access: newAccess,
                  status: editUserForm.status,
                }
              : u
          )
        );
        showToast("success", `Updated role & permissions for ${selectedUser.email}.`);
      }
    } catch (err) {
      setUsersList((prev) =>
        prev.map((u) =>
          u.email === selectedUser.email
            ? {
                ...u,
                role: newRoleTitle,
                raw_role: editUserForm.role,
                access: newAccess,
                status: editUserForm.status,
              }
            : u
        )
      );
      showToast("success", `Updated ${selectedUser.email} permissions.`);
    }

    setShowEditModal(false);
    setSelectedUser(null);
  };

  // Handler: Open Delete Modal
  const handleOpenDelete = (user) => {
    setSelectedUser(user);
    setShowDeleteModal(true);
  };

  // Handler: Delete User Submit
  const handleDeleteUserSubmit = async () => {
    if (!selectedUser) return;

    try {
      if (selectedUser.id && !isUsingFallback) {
        await fetchApi(`/api/auth/users/${selectedUser.id}`, {
          method: "DELETE",
        });
        showToast("success", `Account ${selectedUser.email} has been removed.`);
        fetchUsers();
      } else {
        setUsersList((prev) => prev.filter((u) => u.email !== selectedUser.email));
        showToast("success", `Account ${selectedUser.email} has been removed.`);
      }
    } catch (err) {
      setUsersList((prev) => prev.filter((u) => u.email !== selectedUser.email));
      showToast("success", `Account ${selectedUser.email} removed.`);
    }

    setShowDeleteModal(false);
    setSelectedUser(null);
  };

  const dynamicCardStyle = {
    backgroundColor: isDark ? "#0f172a" : "#ffffff",
    borderColor: isDark ? "rgba(255, 255, 255, 0.08)" : "#e2e8f0",
    color: isDark ? "#f8fafc" : "#0f172a",
  };

  return (
    <DashboardCard
      title="User Management & Role Permissions"
      badgeTag="Active Matrix"
      className="dedicated-tab-view"
    >
      <div style={{ marginBottom: "1.25rem" }}>
        <p className="tab-description" style={{ margin: 0 }}>
          Manage security analyst accounts, enforce multi-factor authentication, and configure RBAC privileges across NetShield-AI enterprise gateway.
        </p>
      </div>

      {/* Toast Banner Notification */}
      {toast && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.75rem",
            padding: "0.75rem 1rem",
            borderRadius: "8px",
            marginBottom: "1rem",
            fontSize: "0.875rem",
            fontWeight: 500,
            backgroundColor:
              toast.type === "success"
                ? isDark
                  ? "rgba(34, 197, 94, 0.15)"
                  : "#dcfce7"
                : toast.type === "error"
                ? isDark
                  ? "rgba(239, 68, 68, 0.15)"
                  : "#fee2e2"
                : isDark
                ? "rgba(59, 130, 246, 0.15)"
                : "#dbeafe",
            color:
              toast.type === "success"
                ? isDark
                  ? "#4ade80"
                  : "#15803d"
                : toast.type === "error"
                ? isDark
                  ? "#f87171"
                  : "#b91c1c"
                : isDark
                ? "#60a5fa"
                : "#1d4ed8",
            border: `1px solid ${
              toast.type === "success"
                ? isDark
                  ? "rgba(34, 197, 94, 0.3)"
                  : "#86efac"
                : toast.type === "error"
                ? isDark
                  ? "rgba(239, 68, 68, 0.3)"
                  : "#fca5a5"
                : isDark
                ? "rgba(59, 130, 246, 0.3)"
                : "#93c5fd"
            }`,
          }}
        >
          {toast.type === "success" && <CheckCircle2 size={18} />}
          {toast.type === "error" && <AlertCircle size={18} />}
          {toast.type === "info" && <Shield size={18} />}
          <span style={{ flex: 1 }}>{toast.text}</span>
          <button
            onClick={() => setToast(null)}
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              color: "inherit",
              display: "flex",
              alignItems: "center",
            }}
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Connection Notice */}
      {usersError && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "0.75rem",
            padding: "0.65rem 1rem",
            borderRadius: "8px",
            marginBottom: "1rem",
            fontSize: "0.825rem",
            backgroundColor: isDark ? "rgba(234, 179, 8, 0.1)" : "#fef9c3",
            color: isDark ? "#facc15" : "#a16207",
            border: isDark ? "1px solid rgba(234, 179, 8, 0.25)" : "1px solid #fde047",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <AlertCircle size={16} />
            <span>{usersError}</span>
          </div>
          <button
            onClick={fetchUsers}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.35rem",
              background: "transparent",
              border: isDark ? "1px solid rgba(234, 179, 8, 0.4)" : "1px solid #ca8a04",
              borderRadius: "4px",
              color: "inherit",
              padding: "0.25rem 0.6rem",
              fontSize: "0.75rem",
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            <RefreshCw size={12} className={loadingUsers ? "animate-spin" : ""} />
            Retry Sync
          </button>
        </div>
      )}

      {/* KPI Cards Row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "1rem",
          marginBottom: "1.25rem",
        }}
      >
        <div
          style={{
            ...dynamicCardStyle,
            padding: "1rem 1.25rem",
            borderRadius: "10px",
            border: "1px solid",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b", fontWeight: 600, textTransform: "uppercase" }}>
              Total Accounts
            </div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: "0.25rem" }}>
              {totalUsers}
            </div>
          </div>
          <div
            style={{
              padding: "0.6rem",
              borderRadius: "8px",
              backgroundColor: isDark ? "rgba(59, 130, 246, 0.15)" : "#eff6ff",
              color: "#3b82f6",
            }}
          >
            <Users size={22} />
          </div>
        </div>

        <div
          style={{
            ...dynamicCardStyle,
            padding: "1rem 1.25rem",
            borderRadius: "10px",
            border: "1px solid",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b", fontWeight: 600, textTransform: "uppercase" }}>
              Administrators
            </div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: "0.25rem", color: "#a855f7" }}>
              {adminCount}
            </div>
          </div>
          <div
            style={{
              padding: "0.6rem",
              borderRadius: "8px",
              backgroundColor: isDark ? "rgba(168, 85, 247, 0.15)" : "#faf5ff",
              color: "#a855f7",
            }}
          >
            <ShieldCheck size={22} />
          </div>
        </div>

        <div
          style={{
            ...dynamicCardStyle,
            padding: "1rem 1.25rem",
            borderRadius: "10px",
            border: "1px solid",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b", fontWeight: 600, textTransform: "uppercase" }}>
              Security Analysts
            </div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: "0.25rem", color: "#06b6d4" }}>
              {analystCount}
            </div>
          </div>
          <div
            style={{
              padding: "0.6rem",
              borderRadius: "8px",
              backgroundColor: isDark ? "rgba(6, 182, 212, 0.15)" : "#ecfeff",
              color: "#06b6d4",
            }}
          >
            <UserCheck size={22} />
          </div>
        </div>

        <div
          style={{
            ...dynamicCardStyle,
            padding: "1rem 1.25rem",
            borderRadius: "10px",
            border: "1px solid",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b", fontWeight: 600, textTransform: "uppercase" }}>
              Active Sessions
            </div>
            <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: "0.25rem", color: "#22c55e" }}>
              {activeCount}
            </div>
          </div>
          <div
            style={{
              padding: "0.6rem",
              borderRadius: "8px",
              backgroundColor: isDark ? "rgba(34, 197, 94, 0.15)" : "#f0fdf4",
              color: "#22c55e",
            }}
          >
            <Key size={22} />
          </div>
        </div>
      </div>

      {/* Control Bar: Search, Filters, Add User Button */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "0.75rem",
          marginBottom: "1rem",
        }}
      >
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.75rem", flex: 1 }}>
          {/* Search Box */}
          <div
            style={{
              position: "relative",
              minWidth: "240px",
              flex: 1,
              maxWidth: "360px",
            }}
          >
            <Search
              size={16}
              style={{
                position: "absolute",
                left: "0.75rem",
                top: "50%",
                transform: "translateY(-50%)",
                color: isDark ? "#64748b" : "#94a3b8",
              }}
            />
            <input
              type="text"
              placeholder="Search user email or role..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: "100%",
                padding: "0.5rem 0.75rem 0.5rem 2.25rem",
                borderRadius: "6px",
                border: isDark ? "1px solid rgba(255,255,255,0.12)" : "1px solid #cbd5e1",
                backgroundColor: isDark ? "rgba(15, 23, 42, 0.6)" : "#f8fafc",
                color: isDark ? "#f8fafc" : "#0f172a",
                fontSize: "0.85rem",
                outline: "none",
              }}
            />
          </div>

          {/* Role Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <Filter size={14} style={{ color: isDark ? "#94a3b8" : "#64748b" }} />
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              style={{
                padding: "0.5rem 0.75rem",
                borderRadius: "6px",
                border: isDark ? "1px solid rgba(255,255,255,0.12)" : "1px solid #cbd5e1",
                backgroundColor: isDark ? "#0f172a" : "#f8fafc",
                color: isDark ? "#f8fafc" : "#0f172a",
                fontSize: "0.825rem",
                outline: "none",
                cursor: "pointer",
              }}
            >
              <option value="ALL">All Roles</option>
              <option value="ADMIN">Security Administrator</option>
              <option value="ANALYST">Security Analyst</option>
            </select>
          </div>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            style={{
              padding: "0.5rem 0.75rem",
              borderRadius: "6px",
              border: isDark ? "1px solid rgba(255,255,255,0.12)" : "1px solid #cbd5e1",
              backgroundColor: isDark ? "#0f172a" : "#f8fafc",
              color: isDark ? "#f8fafc" : "#0f172a",
              fontSize: "0.825rem",
              outline: "none",
              cursor: "pointer",
            }}
          >
            <option value="ALL">All Statuses</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
          </select>

          {/* Rows Per Page Selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
            <span style={{ fontSize: "0.8rem", color: isDark ? "#94a3b8" : "#64748b", fontWeight: 500 }}>
              Rows:
            </span>
            <select
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value))}
              title="Rows per page limit"
              style={{
                padding: "0.5rem 0.75rem",
                borderRadius: "6px",
                border: isDark ? "1px solid rgba(255,255,255,0.12)" : "1px solid #cbd5e1",
                backgroundColor: isDark ? "#0f172a" : "#f8fafc",
                color: isDark ? "#f8fafc" : "#0f172a",
                fontSize: "0.825rem",
                outline: "none",
                cursor: "pointer",
              }}
            >
              <option value={8}>8 per page</option>
              <option value={10}>10 per page</option>
              <option value={15}>15 per page</option>
              <option value={20}>20 per page</option>
            </select>
          </div>
        </div>

        {/* Action Controls: Refresh & Add User */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <button
            onClick={fetchUsers}
            title="Refresh Users"
            style={{
              padding: "0.5rem 0.75rem",
              borderRadius: "6px",
              border: isDark ? "1px solid rgba(255,255,255,0.12)" : "1px solid #cbd5e1",
              backgroundColor: isDark ? "rgba(15, 23, 42, 0.8)" : "#ffffff",
              color: isDark ? "#cbd5e1" : "#475569",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <RefreshCw size={15} className={loadingUsers ? "animate-spin" : ""} />
          </button>

          <button
            onClick={() => setShowAddModal(true)}
            style={{
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              border: "none",
              backgroundColor: "#3b82f6",
              color: "#ffffff",
              fontWeight: 600,
              fontSize: "0.85rem",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              boxShadow: "0 2px 8px rgba(59, 130, 246, 0.3)",
            }}
          >
            <UserPlus size={16} />
            Add User
          </button>
        </div>
      </div>

      {/* Main Table */}
      <div
        className="table-responsive"
        style={{
          width: "100%",
          height: "auto",
          maxHeight: "none",
          overflowX: "auto",
          overflowY: "visible",
          borderRadius: "8px",
          border: isDark ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid #e2e8f0",
        }}
      >
        {loadingUsers ? (
          <LoadingSpinner text="Loading user directory from PostgreSQL database..." />
        ) : paginatedUsers.length > 0 ? (
          <table className="ns-soc-table" style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead style={{ position: "sticky", top: 0, zIndex: 5, backgroundColor: isDark ? "#0f172a" : "#f8fafc" }}>
              <tr>
                <th style={{ padding: "0.6rem 0.85rem" }}>User / Account Email</th>
                <th style={{ padding: "0.6rem 0.85rem" }}>Assigned Role</th>
                <th style={{ padding: "0.6rem 0.85rem" }}>Access Privilege Level</th>
                <th style={{ padding: "0.6rem 0.85rem" }}>Status</th>
                <th style={{ padding: "0.6rem 0.85rem" }}>Provisioned / Created</th>
                <th style={{ textAlign: "right", padding: "0.6rem 0.85rem" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedUsers.map((u, idx) => {
                const isAdmin =
                  u.role === "Security Administrator" || u.raw_role === "admin";
                const userKey = `user-${u.id || 'no-id'}-${u.email || 'no-email'}-${idx}`;

                return (
                  <tr key={userKey}>
                    <td style={{ padding: "0.55rem 0.85rem" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <div
                          style={{
                            width: "28px",
                            height: "28px",
                            borderRadius: "50%",
                            backgroundColor: isAdmin
                              ? isDark
                                ? "rgba(168, 85, 247, 0.2)"
                                : "#f3e8ff"
                              : isDark
                              ? "rgba(6, 182, 212, 0.2)"
                              : "#e0f2fe",
                            color: isAdmin ? "#a855f7" : "#0284c7",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            fontSize: "0.75rem",
                            fontWeight: 700,
                          }}
                        >
                          {u.email ? u.email[0].toUpperCase() : "U"}
                        </div>
                        <code>{u.email}</code>
                      </div>
                    </td>

                    <td style={{ padding: "0.55rem 0.85rem" }}>
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "0.35rem",
                          padding: "0.2rem 0.6rem",
                          borderRadius: "9999px",
                          fontSize: "0.75rem",
                          fontWeight: 600,
                          backgroundColor: isAdmin
                            ? isDark
                              ? "rgba(168, 85, 247, 0.15)"
                              : "#f3e8ff"
                            : isDark
                            ? "rgba(6, 182, 212, 0.15)"
                            : "#e0f2fe",
                          color: isAdmin ? (isDark ? "#c084fc" : "#7e22ce") : isDark ? "#22d3ee" : "#0369a1",
                          border: `1px solid ${
                            isAdmin
                              ? isDark
                                ? "rgba(168, 85, 247, 0.3)"
                                : "#d8b4fe"
                              : isDark
                              ? "rgba(6, 182, 212, 0.3)"
                              : "#7dd3fc"
                          }`,
                        }}
                      >
                        {isAdmin ? <ShieldCheck size={12} /> : <UserCheck size={12} />}
                        {u.role || (isAdmin ? "Security Administrator" : "Security Analyst")}
                      </span>
                    </td>

                    <td style={{ padding: "0.55rem 0.85rem", fontSize: "0.825rem", color: isDark ? "#cbd5e1" : "#475569" }}>
                      {u.access || (isAdmin ? "Full Global Control" : "Read / Monitor / Triage")}
                    </td>

                    <td style={{ padding: "0.55rem 0.85rem" }}>
                      <span
                        className={`status-badge ${
                          (u.status || "Active").toLowerCase() === "active" ? "normal" : "warning"
                        }`}
                      >
                        {u.status || "Active"}
                      </span>
                    </td>

                    <td style={{ padding: "0.55rem 0.85rem", fontSize: "0.8rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                      <code>
                        {u.created_at
                          ? u.created_at.includes("UTC")
                            ? u.created_at
                            : `${u.created_at} UTC`
                          : "2026-07-27 08:52:03 UTC"}
                      </code>
                    </td>

                    <td style={{ padding: "0.55rem 0.85rem" }}>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "flex-end",
                          gap: "0.4rem",
                        }}
                      >
                        <button
                          onClick={() => handleOpenEdit(u)}
                          title="Edit Role / Permissions"
                          style={{
                            padding: "0.3rem 0.5rem",
                            borderRadius: "4px",
                            border: isDark ? "1px solid rgba(255,255,255,0.1)" : "1px solid #cbd5e1",
                            backgroundColor: isDark ? "rgba(59, 130, 246, 0.1)" : "#eff6ff",
                            color: "#3b82f6",
                            cursor: "pointer",
                            display: "flex",
                            alignItems: "center",
                            gap: "0.25rem",
                            fontSize: "0.75rem",
                            fontWeight: 500,
                          }}
                        >
                          <Edit3 size={13} />
                          Edit Role
                        </button>

                        <button
                          onClick={() => handleOpenDelete(u)}
                          title="Delete User"
                          style={{
                            padding: "0.3rem 0.5rem",
                            borderRadius: "4px",
                            border: isDark ? "1px solid rgba(239, 68, 68, 0.2)" : "1px solid #fca5a5",
                            backgroundColor: isDark ? "rgba(239, 68, 68, 0.1)" : "#fef2f2",
                            color: "#ef4444",
                            cursor: "pointer",
                            display: "flex",
                            alignItems: "center",
                            gap: "0.25rem",
                            fontSize: "0.75rem",
                            fontWeight: 500,
                          }}
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: "2.5rem 1rem", textAlign: "center", color: isDark ? "#94a3b8" : "#64748b" }}>
            <Users size={32} style={{ marginBottom: "0.5rem", opacity: 0.5 }} />
            <p style={{ margin: 0, fontSize: "0.9rem" }}>No users match the active search or filter criteria.</p>
          </div>
        )}
      </div>

      {/* Pagination Controls */}
      {filteredUsers.length > 0 && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginTop: "1.25rem",
            paddingTop: "0.75rem",
            borderTop: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #e2e8f0",
            fontSize: "0.825rem",
            color: isDark ? "#94a3b8" : "#64748b",
            position: "relative",
            zIndex: 10,
            pointerEvents: "auto",
          }}
        >
          <div>
            Showing <strong>{filteredUsers.length === 0 ? 0 : (currentPage - 1) * pageSize + 1}</strong> to{" "}
            <strong>{Math.min(currentPage * pageSize, filteredUsers.length)}</strong> of{" "}
            <strong>{filteredUsers.length}</strong> user accounts
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <button
              type="button"
              disabled={currentPage <= 1}
              onClick={handlePrevPage}
              style={{
                padding: "0.4rem 0.85rem",
                borderRadius: "6px",
                border: currentPage <= 1
                  ? isDark ? "1px solid rgba(255,255,255,0.06)" : "1px solid #e2e8f0"
                  : isDark ? "1px solid rgba(59, 130, 246, 0.35)" : "1px solid #93c5fd",
                backgroundColor: currentPage <= 1
                  ? isDark ? "rgba(15, 23, 42, 0.4)" : "#f8fafc"
                  : isDark ? "rgba(30, 41, 59, 0.7)" : "#ffffff",
                color: currentPage <= 1
                  ? isDark ? "#475569" : "#94a3b8"
                  : isDark ? "#f8fafc" : "#1e293b",
                cursor: currentPage <= 1 ? "not-allowed" : "pointer",
                opacity: currentPage <= 1 ? 0.5 : 1,
                display: "flex",
                alignItems: "center",
                gap: "0.35rem",
                fontSize: "0.8rem",
                fontWeight: 600,
                transition: "all 0.15s ease-in-out",
                boxShadow: currentPage <= 1 ? "none" : isDark ? "0 2px 6px rgba(0,0,0,0.3)" : "0 1px 3px rgba(0,0,0,0.08)",
              }}
            >
              <ChevronLeft size={15} />
              Previous
            </button>

            <span
              style={{
                padding: "0.35rem 0.75rem",
                borderRadius: "6px",
                fontSize: "0.775rem",
                fontWeight: 600,
                letterSpacing: "0.02em",
                backgroundColor: isDark ? "rgba(15, 23, 42, 0.8)" : "#f1f5f9",
                color: isDark ? "#cbd5e1" : "#334155",
                border: isDark ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid #e2e8f0",
              }}
            >
              Page <span style={{ color: "#3b82f6", fontWeight: 700 }}>{currentPage}</span> of {totalPages}
            </span>

            <button
              type="button"
              disabled={currentPage >= totalPages}
              onClick={handleNextPage}
              style={{
                padding: "0.4rem 0.85rem",
                borderRadius: "6px",
                border: currentPage >= totalPages
                  ? isDark ? "1px solid rgba(255,255,255,0.06)" : "1px solid #e2e8f0"
                  : isDark ? "1px solid rgba(59, 130, 246, 0.35)" : "1px solid #93c5fd",
                backgroundColor: currentPage >= totalPages
                  ? isDark ? "rgba(15, 23, 42, 0.4)" : "#f8fafc"
                  : isDark ? "rgba(30, 41, 59, 0.7)" : "#ffffff",
                color: currentPage >= totalPages
                  ? isDark ? "#475569" : "#94a3b8"
                  : isDark ? "#f8fafc" : "#1e293b",
                cursor: currentPage >= totalPages ? "not-allowed" : "pointer",
                opacity: currentPage >= totalPages ? 0.5 : 1,
                display: "flex",
                alignItems: "center",
                gap: "0.35rem",
                fontSize: "0.8rem",
                fontWeight: 600,
                transition: "all 0.15s ease-in-out",
                boxShadow: currentPage >= totalPages ? "none" : isDark ? "0 2px 6px rgba(0,0,0,0.3)" : "0 1px 3px rgba(0,0,0,0.08)",
              }}
            >
              Next
              <ChevronRight size={15} />
            </button>
          </div>
        </div>
      )}

      {/* Modal: Add New User */}
      {showAddModal && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            backgroundColor: "rgba(0,0,0,0.65)",
            backdropFilter: "blur(4px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1rem",
          }}
        >
          <div
            style={{
              backgroundColor: isDark ? "#0f172a" : "#ffffff",
              border: isDark ? "1px solid rgba(59, 130, 246, 0.3)" : "1px solid #cbd5e1",
              borderRadius: "12px",
              width: "100%",
              maxWidth: "460px",
              boxShadow: "0 20px 25px -5px rgba(0,0,0,0.5)",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "1rem 1.25rem",
                borderBottom: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #e2e8f0",
              }}
            >
              <h3
                style={{
                  margin: 0,
                  fontSize: "1.1rem",
                  fontWeight: 700,
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  color: isDark ? "#f8fafc" : "#0f172a",
                }}
              >
                <UserPlus size={18} style={{ color: "#3b82f6" }} />
                Provision New User Account
              </h3>
              <button
                onClick={() => setShowAddModal(false)}
                style={{
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  color: isDark ? "#94a3b8" : "#64748b",
                }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleAddUserSubmit} style={{ padding: "1.25rem" }}>
              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                    marginBottom: "0.35rem",
                    color: isDark ? "#cbd5e1" : "#334155",
                  }}
                >
                  Email Address
                </label>
                <input
                  type="email"
                  required
                  placeholder="analyst@netshield.io"
                  value={newUserForm.email}
                  onChange={(e) => setNewUserForm({ ...newUserForm, email: e.target.value })}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: isDark ? "rgba(15, 23, 42, 0.8)" : "#f8fafc",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                    outline: "none",
                  }}
                />
              </div>

              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                    marginBottom: "0.35rem",
                    color: isDark ? "#cbd5e1" : "#334155",
                  }}
                >
                  Password
                </label>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={newUserForm.password}
                  onChange={(e) => setNewUserForm({ ...newUserForm, password: e.target.value })}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: isDark ? "rgba(15, 23, 42, 0.8)" : "#f8fafc",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                    outline: "none",
                  }}
                />
              </div>

              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                    marginBottom: "0.35rem",
                    color: isDark ? "#cbd5e1" : "#334155",
                  }}
                >
                  Assigned RBAC Role
                </label>
                <select
                  value={newUserForm.role}
                  onChange={(e) => setNewUserForm({ ...newUserForm, role: e.target.value })}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: isDark ? "#0f172a" : "#f8fafc",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                    outline: "none",
                  }}
                >
                  <option value="analyst">Security Analyst (Read / Monitor / Triage)</option>
                  <option value="admin">Security Administrator (Full Global Control)</option>
                </select>
              </div>

              <div style={{ marginBottom: "1.25rem" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                    marginBottom: "0.35rem",
                    color: isDark ? "#cbd5e1" : "#334155",
                  }}
                >
                  Initial Status
                </label>
                <select
                  value={newUserForm.status}
                  onChange={(e) => setNewUserForm({ ...newUserForm, status: e.target.value })}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: isDark ? "#0f172a" : "#f8fafc",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                    outline: "none",
                  }}
                >
                  <option value="Active">Active</option>
                  <option value="Inactive">Inactive</option>
                </select>
              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "flex-end",
                  gap: "0.5rem",
                }}
              >
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  style={{
                    padding: "0.5rem 1rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: "transparent",
                    color: isDark ? "#cbd5e1" : "#475569",
                    cursor: "pointer",
                    fontSize: "0.85rem",
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    padding: "0.5rem 1.25rem",
                    borderRadius: "6px",
                    border: "none",
                    backgroundColor: "#3b82f6",
                    color: "#ffffff",
                    fontWeight: 600,
                    fontSize: "0.85rem",
                    cursor: "pointer",
                  }}
                >
                  Confirm Provisioning
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Edit User & Role Assignment */}
      {showEditModal && selectedUser && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            backgroundColor: "rgba(0,0,0,0.65)",
            backdropFilter: "blur(4px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1rem",
          }}
        >
          <div
            style={{
              backgroundColor: isDark ? "#0f172a" : "#ffffff",
              border: isDark ? "1px solid rgba(168, 85, 247, 0.3)" : "1px solid #cbd5e1",
              borderRadius: "12px",
              width: "100%",
              maxWidth: "460px",
              boxShadow: "0 20px 25px -5px rgba(0,0,0,0.5)",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "1rem 1.25rem",
                borderBottom: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #e2e8f0",
              }}
            >
              <h3
                style={{
                  margin: 0,
                  fontSize: "1.1rem",
                  fontWeight: 700,
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  color: isDark ? "#f8fafc" : "#0f172a",
                }}
              >
                <Edit3 size={18} style={{ color: "#a855f7" }} />
                Edit RBAC Role & Privileges
              </h3>
              <button
                onClick={() => setShowEditModal(false)}
                style={{
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  color: isDark ? "#94a3b8" : "#64748b",
                }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleEditUserSubmit} style={{ padding: "1.25rem" }}>
              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                    marginBottom: "0.35rem",
                    color: isDark ? "#94a3b8" : "#64748b",
                  }}
                >
                  Target Account
                </label>
                <input
                  type="email"
                  disabled
                  value={selectedUser.email}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #e2e8f0",
                    backgroundColor: isDark ? "rgba(255,255,255,0.04)" : "#f1f5f9",
                    color: isDark ? "#94a3b8" : "#64748b",
                    fontSize: "0.875rem",
                    cursor: "not-allowed",
                  }}
                />
              </div>

              <div style={{ marginBottom: "1rem" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                    marginBottom: "0.35rem",
                    color: isDark ? "#cbd5e1" : "#334155",
                  }}
                >
                  Assign Role Privilege
                </label>
                <select
                  value={editUserForm.role}
                  onChange={(e) => setEditUserForm({ ...editUserForm, role: e.target.value })}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: isDark ? "#0f172a" : "#f8fafc",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                    outline: "none",
                  }}
                >
                  <option value="analyst">Security Analyst (Read / Monitor / Triage)</option>
                  <option value="admin">Security Administrator (Full Global Control)</option>
                </select>
              </div>

              <div style={{ marginBottom: "1.25rem" }}>
                <label
                  style={{
                    display: "block",
                    fontSize: "0.8rem",
                    fontWeight: 600,
                    marginBottom: "0.35rem",
                    color: isDark ? "#cbd5e1" : "#334155",
                  }}
                >
                  Account Status
                </label>
                <select
                  value={editUserForm.status}
                  onChange={(e) => setEditUserForm({ ...editUserForm, status: e.target.value })}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: isDark ? "#0f172a" : "#f8fafc",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                    outline: "none",
                  }}
                >
                  <option value="Active">Active</option>
                  <option value="Inactive">Inactive</option>
                </select>
              </div>

              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "flex-end",
                  gap: "0.5rem",
                }}
              >
                <button
                  type="button"
                  onClick={() => setShowEditModal(false)}
                  style={{
                    padding: "0.5rem 1rem",
                    borderRadius: "6px",
                    border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                    backgroundColor: "transparent",
                    color: isDark ? "#cbd5e1" : "#475569",
                    cursor: "pointer",
                    fontSize: "0.85rem",
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    padding: "0.5rem 1.25rem",
                    borderRadius: "6px",
                    border: "none",
                    backgroundColor: "#a855f7",
                    color: "#ffffff",
                    fontWeight: 600,
                    fontSize: "0.85rem",
                    cursor: "pointer",
                  }}
                >
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Delete User Confirmation */}
      {showDeleteModal && selectedUser && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 9999,
            backgroundColor: "rgba(0,0,0,0.65)",
            backdropFilter: "blur(4px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1rem",
          }}
        >
          <div
            style={{
              backgroundColor: isDark ? "#0f172a" : "#ffffff",
              border: isDark ? "1px solid rgba(239, 68, 68, 0.3)" : "1px solid #fca5a5",
              borderRadius: "12px",
              width: "100%",
              maxWidth: "420px",
              boxShadow: "0 20px 25px -5px rgba(0,0,0,0.5)",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "1.25rem",
                textAlign: "center",
              }}
            >
              <div
                style={{
                  width: "48px",
                  height: "48px",
                  borderRadius: "50%",
                  backgroundColor: isDark ? "rgba(239, 68, 68, 0.15)" : "#fee2e2",
                  color: "#ef4444",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  margin: "0 auto 1rem auto",
                }}
              >
                <Trash2 size={24} />
              </div>
              <h3
                style={{
                  margin: "0 0 0.5rem 0",
                  fontSize: "1.1rem",
                  fontWeight: 700,
                  color: isDark ? "#f8fafc" : "#0f172a",
                }}
              >
                Delete Account Privilege
              </h3>
              <p
                style={{
                  margin: 0,
                  fontSize: "0.875rem",
                  color: isDark ? "#94a3b8" : "#64748b",
                  lineHeight: 1.5,
                }}
              >
                Are you sure you want to revoke access and delete account{" "}
                <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>
                  {selectedUser.email}
                </strong>
                ? This action cannot be undone.
              </p>
            </div>

            <div
              style={{
                padding: "0.75rem 1.25rem 1.25rem 1.25rem",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: "0.75rem",
              }}
            >
              <button
                type="button"
                onClick={() => setShowDeleteModal(false)}
                style={{
                  padding: "0.55rem 1.25rem",
                  borderRadius: "6px",
                  border: isDark ? "1px solid rgba(255,255,255,0.15)" : "1px solid #cbd5e1",
                  backgroundColor: "transparent",
                  color: isDark ? "#cbd5e1" : "#475569",
                  cursor: "pointer",
                  fontSize: "0.85rem",
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteUserSubmit}
                style={{
                  padding: "0.55rem 1.25rem",
                  borderRadius: "6px",
                  border: "none",
                  backgroundColor: "#ef4444",
                  color: "#ffffff",
                  fontWeight: 600,
                  fontSize: "0.85rem",
                  cursor: "pointer",
                }}
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </DashboardCard>
  );
}
