package ai.opencode.app;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;

/**
 * Minimal wrapping container: lays children left-to-right and wraps to the
 * next line when the available width is exceeded. Used for the question
 * tool's option pills so long labels flow onto multiple lines instead of
 * overflowing the card (which used to squeeze the last pill into a narrow
 * column and inflate the whole card's height).
 */
public final class FlowLayout extends ViewGroup {
    private final int hGap;
    private final int vGap;

    public FlowLayout(Context c, int hGapDp, int vGapDp) {
        super(c);
        float d = c.getResources().getDisplayMetrics().density;
        this.hGap = (int) (hGapDp * d + 0.5f);
        this.vGap = (int) (vGapDp * d + 0.5f);
    }

    public FlowLayout(Context c, AttributeSet attrs) {
        super(c, attrs);
        float d = c.getResources().getDisplayMetrics().density;
        this.hGap = (int) (6 * d + 0.5f);
        this.vGap = (int) (6 * d + 0.5f);
    }

    @Override
    protected LayoutParams generateDefaultLayoutParams() {
        return new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
    }

    @Override
    public LayoutParams generateLayoutParams(AttributeSet attrs) {
        return new LayoutParams(getContext(), attrs);
    }

    @Override
    protected void onMeasure(int wSpec, int hSpec) {
        int widthMode = MeasureSpec.getMode(wSpec);
        int widthSize = MeasureSpec.getSize(wSpec);
        int avail = widthMode == MeasureSpec.UNSPECIFIED
                ? Integer.MAX_VALUE
                : Math.max(0, widthSize - getPaddingLeft() - getPaddingRight());

        int used = 0;
        int lineH = 0;
        int totalH = 0;
        int maxLineW = 0;
        int count = getChildCount();
        for (int i = 0; i < count; i++) {
            View ch = getChildAt(i);
            if (ch.getVisibility() == GONE) continue;
            measureChild(ch, wSpec, hSpec);
            int cw = ch.getMeasuredWidth();
            int chh = ch.getMeasuredHeight();
            if (used > 0 && used + hGap + cw > avail) {
                maxLineW = Math.max(maxLineW, used);
                totalH += lineH + vGap;
                used = cw;
                lineH = chh;
            } else {
                used += (used > 0 ? hGap : 0) + cw;
                lineH = Math.max(lineH, chh);
            }
        }
        maxLineW = Math.max(maxLineW, used);
        totalH += lineH;

        int desiredW = maxLineW + getPaddingLeft() + getPaddingRight();
        int desiredH = totalH + getPaddingTop() + getPaddingBottom();
        setMeasuredDimension(
                resolveSize(desiredW, wSpec),
                resolveSize(desiredH, hSpec));
    }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b) {
        int padL = getPaddingLeft();
        int padT = getPaddingTop();
        int avail = Math.max(0, (r - l) - padL - getPaddingRight());

        int used = 0;
        int lineH = 0;
        int x = padL;
        int y = padT;
        int count = getChildCount();
        for (int i = 0; i < count; i++) {
            View ch = getChildAt(i);
            if (ch.getVisibility() == GONE) continue;
            int cw = ch.getMeasuredWidth();
            int chh = ch.getMeasuredHeight();
            if (used > 0 && used + hGap + cw > avail) {
                x = padL;
                y += lineH + vGap;
                used = 0;
                lineH = 0;
            }
            ch.layout(x, y, x + cw, y + chh);
            x += cw + hGap;
            used += (used > 0 ? hGap : 0) + cw;
            lineH = Math.max(lineH, chh);
        }
    }
}
