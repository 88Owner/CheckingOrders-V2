# TODO: Fix left list display in warehouse-staff.html to show full cutting data

## Plan Breakdown (Approved):
1. ~~Create TODO.md~~ ✅
2. Add `loadSavedItems()` function to fetch fresh data from `/api/nhap-phoi` in warehouse-staff.html.
3. Fix post-save logic in `themMau()`: call `loadSavedItems()` after success to refresh left list.
4. Enhance `renderSavedList()`: display all metrics (mẫu, số m đầu vào, kích thước+SL+SL Loi, số m đã cắt/còn lại/lỗi/thiếu/nhập kho).
5. Verify backend `/api/nhap-phoi` GET returns full DoiTuongCatVai data.
6. Test end-to-end: input → save → left list shows correct full data.
7. attempt_completion.

**Progress**: Step 1/7 ✅

## Next: Edit warehouse-staff.html

